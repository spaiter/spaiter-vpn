package lib

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

func TestParseEncryptionMethod(t *testing.T) {
	cases := map[string]int{
		"": EncryptionXOR, "xor": EncryptionXOR, "1": EncryptionXOR, "NONE": EncryptionNone, "0": EncryptionNone,
		"chacha20": EncryptionChaCha20, "aes-128-gcm": EncryptionAES128GCM, "AES256GCM": EncryptionAES256GCM,
		"aes_192_gcm": EncryptionAES192GCM, "5": EncryptionAES256GCM,
	}
	for in, want := range cases {
		got, err := ParseEncryptionMethod(in)
		if err != nil || got != want {
			t.Errorf("%q: %d %v, want %d", in, got, err, want)
		}
		if back, _ := ParseEncryptionMethod(EncryptionMethodName(want)); back != want {
			t.Errorf("name of %d does not parse back", want)
		}
	}
	if _, err := ParseEncryptionMethod("rot13"); err == nil {
		t.Error("unknown method accepted")
	}
}

func TestNewValidation(t *testing.T) {
	base := Options{Domains: []string{"t.example"}, Resolvers: []string{"127.0.0.1:5353"}, EncryptionMethod: EncryptionXOR, EncryptionKey: "k"}
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.Resolvers = nil
	if _, err := New(bad); err == nil {
		t.Error("no resolvers accepted")
	}
	bad = base
	bad.Resolvers = []string{"not-an-ip"}
	if _, err := New(bad); err == nil {
		t.Error("invalid resolver accepted")
	}
	bad = base
	bad.Domains = nil
	if _, err := New(bad); err == nil {
		t.Error("no domain accepted")
	}
	bad = base
	bad.EncryptionKey = ""
	if _, err := New(bad); err == nil {
		t.Error("missing key accepted")
	}
	bad = base
	bad.Mode = "udp"
	if _, err := New(bad); err == nil {
		t.Error("unknown mode accepted")
	}
	c, err := New(Options{Domains: []string{"t.example"}, Resolvers: []string{"10.0.0.0/30:53"}, EncryptionMethod: EncryptionNone, Mode: "tcp",
		Tune: func(cfg *config.ClientConfig) {
			cfg.PacketDuplicationCount = 1
			cfg.RX_TX_Workers = 2
			cfg.TunnelProcessWorkers = 3
		}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.Config()
	if cfg.ProtocolType != "TCP" || len(cfg.Resolvers) != 2 || cfg.PacketDuplicationCount != 1 || cfg.ListenPort != 0 || cfg.LocalDNSCachePersist || cfg.RX_TX_Workers != 2 || cfg.TunnelProcessWorkers != 3 {
		t.Fatalf("config: %+v", cfg)
	}
	if _, total := c.Resolvers(); total != 2 {
		t.Fatalf("total resolvers %d", total)
	}
	if _, err := c.Dial(t.Context(), "example.com", 80, time.Second); !errors.Is(err, ErrNotReady) {
		t.Fatalf("dial before run: %v", err)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// startTestServer runs a MasterDnsVPN server on 127.0.0.1 and returns its port and key. extra is
// added to the server's JSON configuration.
func startTestServer(t *testing.T, ctx context.Context, domain string, extra string) (int, string) {
	t.Helper()
	port := freeUDPPort(t)
	keyPath := filepath.Join(t.TempDir(), "key.txt")
	raw := fmt.Sprintf(`{"DOMAIN":[%q],"UDP_HOST":"127.0.0.1","UDP_PORT":%d,"ENCRYPTION_KEY_FILE":%q,"DATA_ENCRYPTION_METHOD":1,"LOG_LEVEL":"ERROR","UDP_READERS":1%s}`, domain, port, keyPath, extra)
	cfg, err := config.LoadServerConfigFromJSONBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		t.Fatal(err)
	}
	srv := udpserver.New(cfg, logger.New("server", "ERROR"), codec)
	go func() {
		if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("server: %v", err)
		}
	}()
	return port, keyInfo.Key
}

func startEcho(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// startUpstreamSOCKS5 runs a SOCKS5 server for the MasterDnsVPN server to forward to. The server
// refuses loopback and private targets itself, so the client dials a name: every name is
// connected to echo, except "refused.test", which gets "connection refused".
func startUpstreamSOCKS5(t *testing.T, echo *net.TCPAddr) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	serve := func(conn net.Conn) {
		defer conn.Close()
		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
			return
		}
		methods := make([]byte, int(head[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		req := make([]byte, 4)
		if _, err := io.ReadFull(conn, req); err != nil || req[1] != 1 {
			return
		}
		var host string
		switch req[3] {
		case 1:
			b := make([]byte, 4)
			_, _ = io.ReadFull(conn, b)
			host = net.IP(b).String()
		case 3:
			l := make([]byte, 1)
			_, _ = io.ReadFull(conn, l)
			b := make([]byte, int(l[0]))
			_, _ = io.ReadFull(conn, b)
			host = string(b)
		case 4:
			b := make([]byte, 16)
			_, _ = io.ReadFull(conn, b)
			host = net.IP(b).String()
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return
		}
		if host == "refused.test" {
			_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		target, err := net.Dial("tcp", echo.String())
		if err != nil {
			_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer target.Close()
		if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		go func() { _, _ = io.Copy(target, conn) }()
		_, _ = io.Copy(conn, target)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

func echoThrough(t *testing.T, conn net.Conn) {
	t.Helper()
	msg := []byte("hello through dns")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo %q", buf)
	}
	_ = conn.Close()
}

func runClient(t *testing.T, ctx context.Context, opts Options) (*Client, chan error) {
	t.Helper()
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx) }()
	readyCtx, readyCancel := context.WithTimeout(ctx, 60*time.Second)
	defer readyCancel()
	if err := c.WaitReady(readyCtx); err != nil {
		t.Fatalf("not ready: %v", err)
	}
	return c, runDone
}

func fastTune(cfg *config.ClientConfig) {
	cfg.MTUTestTimeout = 1
	cfg.PacketDuplicationCount = 1
	cfg.SetupPacketDuplicationCount = 1
}

// In socks5 mode the client dials an echo server, by name, through a MasterDnsVPN server on the
// loopback that forwards to a SOCKS5 server. The socket control is called for the resolver
// sockets and the log lines reach the sink.
func TestClientEndToEndSOCKS5(t *testing.T) {
	if os.Getenv("MASTERDNS_E2E") == "" && testing.Short() {
		t.Skip("short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	const domain = "t.example"
	echo := startEcho(t)
	upstream := startUpstreamSOCKS5(t, echo)
	port, key := startTestServer(t, ctx, domain, fmt.Sprintf(`,"USE_EXTERNAL_SOCKS5":true,"FORWARD_IP":"127.0.0.1","FORWARD_PORT":%d`, upstream.Port))

	controlled := make(chan string, 64)
	logs := make(chan string, 1024)
	c, runDone := runClient(t, ctx, Options{
		Domains:          []string{domain},
		Resolvers:        []string{fmt.Sprintf("127.0.0.1:%d", port)},
		EncryptionMethod: EncryptionXOR,
		EncryptionKey:    key,
		LogLevel:         "info",
		Log: func(level int, message string) {
			select {
			case logs <- message:
			default:
			}
		},
		SocketControl: func(network, address string, rc syscall.RawConn) error {
			select {
			case controlled <- network + " " + address:
			default:
			}
			return nil
		},
		Tune: fastTune,
	})
	if active, total := c.Resolvers(); active != 1 || total != 1 {
		t.Fatalf("resolvers %d/%d", active, total)
	}
	if up, down := c.MTU(); up <= 0 || down <= 0 {
		t.Fatalf("mtu %d/%d", up, down)
	}
	select {
	case <-controlled:
	default:
		t.Fatal("socket control was not called")
	}
	select {
	case <-logs:
	default:
		t.Fatal("no log line reached the sink")
	}

	conn, err := c.Dial(ctx, "echo.test", 80, 30*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	echoThrough(t, conn)

	_, err = c.Dial(ctx, "refused.test", 80, 30*time.Second)
	var connectErr *ConnectError
	if !errors.As(err, &connectErr) || connectErr.Reply != 5 {
		t.Fatalf("refused target: %v", err)
	}

	// the server itself refuses a loopback address
	_, err = c.Dial(ctx, "127.0.0.1", uint16(echo.Port), 30*time.Second)
	if !errors.As(err, &connectErr) || connectErr.Reply != 2 {
		t.Fatalf("loopback target: %v", err)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// In tcp mode the server forwards every stream to its fixed target; host and port given to Dial
// do not matter.
func TestClientEndToEndTCP(t *testing.T) {
	if os.Getenv("MASTERDNS_E2E") == "" && testing.Short() {
		t.Skip("short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	const domain = "t.example"
	echo := startEcho(t)
	port, key := startTestServer(t, ctx, domain, fmt.Sprintf(`,"PROTOCOL_TYPE":"TCP","FORWARD_IP":"127.0.0.1","FORWARD_PORT":%d`, echo.Port))

	c, _ := runClient(t, ctx, Options{
		Domains:          []string{domain},
		Resolvers:        []string{fmt.Sprintf("127.0.0.1:%d", port)},
		EncryptionMethod: EncryptionXOR,
		EncryptionKey:    key,
		Mode:             "tcp",
		LogLevel:         "error",
		Tune:             fastTune,
	})
	conn, err := c.Dial(ctx, "ignored.example", 1, 30*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	echoThrough(t, conn)
}
