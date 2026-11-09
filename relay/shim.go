package main

// wdtt-relay: slim WDTT transport shim.
//
// Terminates the WDTT obfuscation transport (VK-TURN / WRAP / RTP / DTLS) and
// forwards the decapsulated *plain WireGuard* packets to a sing-box WireGuard
// endpoint (wg-wdtt-in). sing-box owns WG termination, routing and the built-in
// BitTorrent sniffer/block — so all WG-over-VK egress passes the torrent filter.
//
// It does NOT run its own WireGuard/NAT and has no Telegram bot: per-user WG
// peers + WRAP passwords are provisioned by our vpn-bot (peer added to sing-box,
// {password -> wg_priv, wg_ip} written into passwords.json). On GETCONF the shim
// just hands the stored config back to the client. The crypto/transport code in
// server.go (listenWrapped / WRAP / RTP / DTLS / buildClientConfig) is reused
// verbatim so existing WDTT/qWDTT clients stay compatible.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

var (
	shimWGEndpoint string // sing-box wg-wdtt-in, e.g. 127.0.0.1:10879
	shimWGPubKey   string // sing-box wg-wdtt-in public key (base64)
)

func shimReloadDB() error {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	data, err := os.ReadFile(dbFile)
	if err != nil {
		return fmt.Errorf("read db: %w", err)
	}
	newDB := &Database{Passwords: map[string]*PasswordEntry{}, Devices: map[string]*ClientDevice{}}
	if err := json.Unmarshal(data, newDB); err != nil {
		return fmt.Errorf("parse db: %w", err)
	}
	newDB.MainPassword = db.MainPassword
	db = newDB
	if db.Passwords == nil {
		db.Passwords = map[string]*PasswordEntry{}
	}
	return refreshWrapKeysFromDBLocked()
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "DTLS/WRAP listen (UDP)")
	wgEndpoint := flag.String("wg-endpoint", "127.0.0.1:10879", "sing-box wg-wdtt-in UDP endpoint")
	wgPubKey := flag.String("wg-pubkey", "", "sing-box wg-wdtt-in public key (base64)")
	configDir := flag.String("config-dir", "/etc/wdtt", "config dir (passwords.json)")
	mainPass := flag.String("password", "", "owner password (optional)")
	dnsFlag := flag.String("dns", "8.8.8.8", "DNS handed to clients in WG config")
	flag.Parse()

	dns = *dnsFlag
	shimWGEndpoint = *wgEndpoint
	shimWGPubKey = *wgPubKey
	if shimWGPubKey == "" {
		log.Fatalf("[SHIM] -wg-pubkey required (sing-box wg-wdtt-in public key)")
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("═══ wdtt-relay (shim) ═══")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// passwords.json -> db + WRAP keys (no WG device / no bot)
	initDB(*configDir, *mainPass, "", "")

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sig {
			if s == syscall.SIGHUP {
				if err := shimReloadDB(); err != nil {
					log.Printf("[SHIM] reload err: %v", err)
				} else {
					log.Printf("[SHIM] reloaded, WRAP keys: %d", serverWrapKeys.Count())
				}
				continue
			}
			cancel()
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}
	}()

	if serverWrapKeys.Count() == 0 {
		log.Printf("[WRAP] no passwords yet — waiting for provisioning (SIGHUP reload)")
	}

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("[SHIM] resolve %s: %v", *listen, err)
	}
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		log.Fatalf("[DTLS] cert: %v", err)
	}
	wrapListener, err := listenWrapped(addr, serverWrapKeys)
	if err != nil {
		log.Fatalf("[WRAP] listen: %v", err)
	}
	listener, err := dtls.NewListenerWithOptions(wrapListener,
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
		dtls.WithMTU(1100))
	if err != nil {
		log.Fatalf("[DTLS] listener: %v", err)
	}
	context.AfterFunc(ctx, func() { listener.Close() })

	log.Printf("   DTLS %s -> sing-box WG %s | WRAP keys: %d", *listen, shimWGEndpoint, serverWrapKeys.Count())
	log.Println("[SHIM] ready")

	for {
		c, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go shimHandleConn(ctx, c)
	}
}

// shimHandleConn: DTLS handshake -> GETCONF/AUTH -> bidirectional pump to sing-box WG.
func shimHandleConn(ctx context.Context, clientConn net.Conn) {
	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}
	hctx, hcancel := context.WithTimeout(ctx, 60*time.Second)
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		hcancel()
		return
	}
	hcancel()

	buf := make([]byte, 1600)
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})
	firstPacket := buf[:n]
	firstStr := string(firstPacket)

	if strings.HasPrefix(firstStr, "GETCONF:") {
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(firstStr, "GETCONF:")), "|")
		clientPort := "9000"
		password := ""
		if len(parts) > 0 {
			clientPort = parts[0]
		}
		if len(parts) > 2 {
			password = parts[2]
		}
		dbMutex.Lock()
		isMain := password != "" && password == db.MainPassword
		entry, isGen := db.Passwords[password]
		switch {
		case isMain:
			// owner password has no per-user WG config; refuse (must use a provisioned pass)
			clientConn.Write([]byte("DENIED:no_wg_for_main"))
			dbMutex.Unlock()
		case !isGen:
			clientConn.Write([]byte("DENIED:wrong_password"))
			dbMutex.Unlock()
		case entry.IsDeactivated:
			clientConn.Write([]byte("DENIED:deactivated"))
			dbMutex.Unlock()
		case isPasswordExpired(entry):
			clientConn.Write([]byte("DENIED:expired"))
			dbMutex.Unlock()
		case entry.WgPriv == "" || entry.WgIP == "":
			clientConn.Write([]byte("NOCONF"))
			dbMutex.Unlock()
		default:
			cfg := buildClientConfig(shimWGPubKey, entry.WgPriv, entry.WgIP, clientPort)
			dbMutex.Unlock()
			clientConn.Write([]byte(cfg))
		}
		clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
	} else if strings.HasPrefix(firstStr, "AUTH:") {
		// AUTH carries no config; just proceed to pump (WRAP already authenticated the password)
		clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
	}

	// ---- pump: client(plain WG) <-> sing-box wg-wdtt-in ----
	wgConn, err := net.Dial("udp", shimWGEndpoint)
	if err != nil {
		return
	}
	defer wgConn.Close()
	if uc, ok := wgConn.(*net.UDPConn); ok {
		uc.SetReadBuffer(2 * 1024 * 1024)
		uc.SetWriteBuffer(2 * 1024 * 1024)
	}
	if _, err := wgConn.Write(firstPacket); err != nil {
		return
	}

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		wgConn.SetDeadline(time.Now())
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client -> WG
		defer wg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			if pctx.Err() != nil {
				return
			}
			clientConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			nn, err := clientConn.Read(*b)
			if err != nil {
				return
			}
			if nn == 1 && (*b)[0] == 0xFF { // DTLS keepalive ping
				continue
			}
			if _, err := wgConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()
	go func() { // WG -> client
		defer wg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			if pctx.Err() != nil {
				return
			}
			wgConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			nn, err := wgConn.Read(*b)
			if err != nil {
				if isNetTimeout(err) && pctx.Err() == nil {
					continue
				}
				return
			}
			if _, err := clientConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}
