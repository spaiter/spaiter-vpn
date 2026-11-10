package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestLibraryPipeTransfer(t *testing.T) {
	a, b := newLibraryPipe()
	defer a.Close()
	defer b.Close()

	payload := bytes.Repeat([]byte("masterdns"), 1000)
	go func() {
		_, _ = a.Write(payload)
		_ = a.Close()
	}()
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
	if _, err := b.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write to a closed peer: %v", err)
	}
}

// A write does not wait for the reader while the buffer is below its limit, and the deadline
// error is a timeout, which the ARQ retries.
func TestLibraryPipeBufferAndDeadline(t *testing.T) {
	old := LibraryPipeBufferLimit
	LibraryPipeBufferLimit = 16
	defer func() { LibraryPipeBufferLimit = old }()

	a, b := newLibraryPipe()
	defer a.Close()
	defer b.Close()

	done := make(chan error, 1)
	go func() {
		_, err := a.Write(make([]byte, 16))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write below the limit waited for a reader")
	}

	_ = a.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := a.Write([]byte("more"))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("full buffer write: %v", err)
	}

	_ = b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := b.Read(buf)
	if n != 16 || err != nil {
		t.Fatalf("read %d %v", n, err)
	}
	_, err = b.Read(buf)
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("empty read with a deadline: %v", err)
	}

	_ = a.SetWriteDeadline(time.Time{})
	_ = b.SetReadDeadline(time.Time{})
	_ = a.Close()
	if _, err := b.Read(buf); err != io.EOF {
		t.Fatalf("read after the peer closed: %v", err)
	}
}

func TestSocksTargetPayload(t *testing.T) {
	p, err := socksTargetPayload("1.2.3.4", 80)
	if err != nil || !bytes.Equal(p, []byte{SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0, 80}) {
		t.Fatalf("ipv4: %v %v", p, err)
	}
	p, err = socksTargetPayload("::1", 443)
	if err != nil || p[0] != SOCKS5_ATYP_IPV6 || len(p) != 1+16+2 || p[16] != 1 {
		t.Fatalf("ipv6: %v %v", p, err)
	}
	p, err = socksTargetPayload("example.com", 8080)
	if err != nil || !bytes.Equal(p, append([]byte{SOCKS5_ATYP_DOMAIN, 11}, append([]byte("example.com"), 0x1f, 0x90)...)) {
		t.Fatalf("domain: %v %v", p, err)
	}
	if _, err := socksTargetPayload("", 1); err == nil {
		t.Fatal("empty host accepted")
	}
}

func TestDialStreamBeforeReady(t *testing.T) {
	c := &Client{}
	if _, err := c.DialStream(t.Context(), "example.com", 80, time.Second); !errors.Is(err, ErrNotReady) {
		t.Fatalf("got %v", err)
	}
}
