package mtproto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// fakeHello builds a ClientHello the way a fake-TLS client does, with an SNI
// for host: the random is HMAC(key, record with random zeroed) XOR
// (28 zero bytes + timestamp).
func fakeHello(t *testing.T, key []byte, host string) []byte {
	t.Helper()
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, clientRandomLen)...)
	session := make([]byte, 32)
	rand.Read(session)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	body = append(body, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	name := []byte(host)
	sni := []byte{0x00, 0x00, 0, 0, 0, 0, 0x00, byte(len(name) >> 8), byte(len(name))}
	sni = append(sni, name...)
	binary.BigEndian.PutUint16(sni[2:4], uint16(len(sni)-4))
	binary.BigEndian.PutUint16(sni[4:6], uint16(len(sni)-6))
	body = append(body, byte(len(sni)>>8), byte(len(sni)))
	body = append(body, sni...)
	handshake := append([]byte{handshakeTypeClient, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{recordTypeHandshake, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))})
	mac.Write(handshake)
	random := mac.Sum(nil)
	var stamp [4]byte
	binary.LittleEndian.PutUint32(stamp[:], uint32(time.Now().Unix()))
	for i := 0; i < 4; i++ {
		random[clientRandomLen-4+i] ^= stamp[i]
	}
	copy(handshake[clientRandomOffset:], random)
	// A real client sends version 0x0303 in the record header; mtg ignores it.
	return append([]byte{recordTypeHandshake, 0x03, 0x03, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

func TestAClientHelloIdentifiesTheUserWhoseKeyMadeIt(t *testing.T) {
	alice, bob := make([]byte, 16), make([]byte, 16)
	rand.Read(alice)
	rand.Read(bob)
	hello := fakeHello(t, alice, "example.com")
	if !clientHelloMatches(hello, alice) {
		t.Fatal("alice's hello was not recognised")
	}
	if clientHelloMatches(hello, bob) {
		t.Fatal("alice's hello was attributed to bob")
	}
	tampered := append([]byte(nil), hello...)
	tampered[len(tampered)-1] ^= 1
	if clientHelloMatches(tampered, alice) {
		t.Fatal("a modified hello still matched")
	}
	for _, short := range [][]byte{nil, hello[:4], hello[:recordHeaderLen+10]} {
		if clientHelloMatches(short, alice) {
			t.Fatal("a truncated hello matched")
		}
	}
}

func TestTheHelloIsReadWholeAndReplayed(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	hello := fakeHello(t, key, "example.com")
	client, server := net.Pipe()
	go func() {
		client.Write(hello)
		client.Write([]byte("rest"))
	}()
	record, err := readClientHello(server, time.Second)
	if err != nil || len(record) != len(hello) {
		t.Fatalf("read %d bytes, %v", len(record), err)
	}
	replay := &replayConn{Conn: server, buffered: record}
	got := make([]byte, len(hello)+4)
	n := 0
	for n < len(got) {
		m, err := replay.Read(got[n:])
		if err != nil {
			t.Fatal(err)
		}
		n += m
	}
	if string(got[:len(hello)]) != string(hello) || string(got[len(hello):]) != "rest" {
		t.Fatal("the replayed stream differs from what the client sent")
	}
}

type recordingRouter struct {
	adapter.Router
	mu       sync.Mutex
	metadata []adapter.InboundContext
}

func (r *recordingRouter) RouteConnectionEx(_ context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.mu.Lock()
	r.metadata = append(r.metadata, metadata)
	r.mu.Unlock()
	conn.Close()
	onClose(nil)
}

type clientContext struct {
	context.Context
	ip net.IP
}

func (c clientContext) ClientIP() net.IP { return c.ip }

func TestTelegramConnectionsAreRoutedAsTheUserFromTheClient(t *testing.T) {
	router := &recordingRouter{}
	network := &mtgNetwork{ctx: context.Background(), router: router, tag: "mtproto-in", user: "alice"}
	conn, err := network.DialContext(clientContext{Context: context.Background(), ip: net.ParseIP("198.51.100.7")}, "tcp", "149.154.167.51:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// mtg asserts this, unchecked, on every data-centre connection it makes.
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || addr.String() != "149.154.167.51:443" {
		t.Fatalf("the routed connection's remote address is %#v, not the data centre's *net.TCPAddr", conn.RemoteAddr())
	}
	deadline := time.Now().Add(time.Second)
	for {
		router.mu.Lock()
		got := len(router.metadata)
		router.mu.Unlock()
		if got > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if len(router.metadata) != 1 {
		t.Fatalf("routed %d connections", len(router.metadata))
	}
	m := router.metadata[0]
	if m.User != "alice" || m.Inbound != "mtproto-in" || m.Source.Addr.String() != "198.51.100.7" || m.Destination.String() != "149.154.167.51:443" {
		t.Fatalf("metadata = %+v", m)
	}
}

// eeSecret is a fake-TLS secret for host with a random key.
func eeSecret(t *testing.T, host string) (string, []byte) {
	t.Helper()
	key := make([]byte, 16)
	rand.Read(key)
	return "ee" + hex.EncodeToString(key) + hex.EncodeToString([]byte(host)), key
}

// serve runs one connection through the inbound and reports whether mtg
// answered with its fake-TLS welcome, which it sends only to a ClientHello it
// validated itself. Anything else gets domain fronting.
func serve(t *testing.T, in *Inbound, hello []byte) bool {
	t.Helper()
	client, server := net.Pipe()
	go in.NewConnection(context.Background(), &tcpAddrConn{Conn: server}, adapter.InboundContext{}, nil)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	go client.Write(hello)
	first := make([]byte, 1)
	_, err := client.Read(first)
	client.Close()
	return err == nil && first[0] == recordTypeHandshake
}

// tcpAddrConn gives a pipe the TCP remote address mtg asserts on.
type tcpAddrConn struct{ net.Conn }

func (c *tcpAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000}
}

func TestMtgAcceptsTheUsersOwnHelloAndFrontsAStrangerAsNobody(t *testing.T) {
	aliceSecret, aliceKey := eeSecret(t, "example.com")
	bobSecret, bobKey := eeSecret(t, "example.com")
	router := &recordingRouter{}
	built, err := NewInbound(context.Background(), router, log.NewNOPFactory().NewLogger("mtproto"), "mtproto-in", option.MTProtoInboundOptions{
		Users: []option.MTProtoUser{{Name: "alice", Secret: aliceSecret}, {Name: "bob", Secret: bobSecret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := built.(*Inbound)
	defer in.Close()
	if !serve(t, in, fakeHello(t, bobKey, "example.com")) {
		t.Fatal("mtg rejected bob's own hello: the digest construction differs from mtg's")
	}
	if !serve(t, in, fakeHello(t, aliceKey, "example.com")) {
		t.Fatal("mtg rejected alice's own hello")
	}

	strangerKey := make([]byte, 16)
	rand.Read(strangerKey)
	if serve(t, in, fakeHello(t, strangerKey, "example.com")) {
		t.Fatal("a stranger's hello was welcomed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		router.mu.Lock()
		routed := append([]adapter.InboundContext(nil), router.metadata...)
		router.mu.Unlock()
		if len(routed) > 0 {
			for _, m := range routed {
				if m.User != "" {
					t.Fatalf("domain fronting for a stranger was routed as %q", m.User)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stranger was not domain-fronted")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestReloadingUsersKeepsUnchangedSessionsAndRecognisesNewUsers(t *testing.T) {
	aliceSecret, aliceKey := eeSecret(t, "example.com")
	bobSecret, bobKey := eeSecret(t, "example.com")
	built, err := NewInbound(context.Background(), &recordingRouter{}, log.NewNOPFactory().NewLogger("mtproto"), "mtproto-in", option.MTProtoInboundOptions{
		Users: []option.MTProtoUser{{Name: "alice", Secret: aliceSecret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := built.(*Inbound)
	defer in.Close()
	aliceProxy := (*in.users.Load())[0].proxy
	if serve(t, in, fakeHello(t, bobKey, "example.com")) {
		t.Fatal("bob was welcomed before he was added")
	}
	if err := in.ReloadUsers(&option.MTProtoInboundOptions{Users: []option.MTProtoUser{{Name: "alice", Secret: aliceSecret}, {Name: "bob", Secret: bobSecret}}}); err != nil {
		t.Fatal(err)
	}
	if (*in.users.Load())[0].proxy != aliceProxy {
		t.Fatal("alice's proxy, and her sessions, were replaced by a reload that did not touch her")
	}
	if !serve(t, in, fakeHello(t, bobKey, "example.com")) {
		t.Fatal("bob is not recognised after being added")
	}
	if err := in.ReloadUsers(&option.MTProtoInboundOptions{Users: []option.MTProtoUser{{Name: "bob", Secret: bobSecret}}}); err != nil {
		t.Fatal(err)
	}
	if serve(t, in, fakeHello(t, aliceKey, "example.com")) {
		t.Fatal("alice is still welcomed after being removed")
	}
	if err := in.ReloadUsers(&option.MTProtoInboundOptions{}); err == nil {
		t.Fatal("a reload to no users was accepted")
	}
}
