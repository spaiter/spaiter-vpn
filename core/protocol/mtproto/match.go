package mtproto

// Identifying the user of a fake-TLS connection before mtg sees it.
//
// A fake-TLS client proves knowledge of its secret in the ClientHello random:
// HMAC-SHA256(secret, record-with-random-zeroed) XOR random leaves 28 zero
// bytes and a timestamp. Checking that per user is how one listener serves
// many secrets; the record is then replayed to that user's mtglib.Proxy, which
// validates it again (hostname, timestamp, anti-replay) exactly as before.
//
// The digest construction is reproduced from mtg's internal faketls package
// (github.com/9seconds/mtg/v2 mtglib/internal/faketls/client_hello.go, MIT
// License, Copyright (c) 2018 Sergey Arkhipov), which is not importable. //H

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	recordHeaderLen      = 5
	recordTypeHandshake  = 0x16
	maxRecordPayload     = 16 << 10
	handshakeTypeClient  = 0x01
	clientRandomOffset   = 6
	clientRandomLen      = 32
	clientHelloMinLength = clientRandomOffset + clientRandomLen
)

// readClientHello reads the first TLS record. Its bytes are returned whole,
// header included, so they can be replayed.
func readClientHello(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		defer conn.SetReadDeadline(time.Time{})
	}
	header := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(conn, header); err != nil {
		return header, err
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if header[0] != recordTypeHandshake || length > maxRecordPayload {
		return header, fmt.Errorf("not a TLS handshake record")
	}
	record := make([]byte, recordHeaderLen+length)
	copy(record, header)
	n, err := io.ReadFull(conn, record[recordHeaderLen:])
	return record[:recordHeaderLen+n], err
}

// clientHelloMatches reports whether a ClientHello record was made with key.
func clientHelloMatches(record, key []byte) bool {
	if len(record) < recordHeaderLen+clientHelloMinLength {
		return false
	}
	handshake := record[recordHeaderLen:]
	if handshake[0] != handshakeTypeClient {
		return false
	}
	declared := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if declared != len(handshake)-4 {
		return false
	}
	var random [clientRandomLen]byte
	copy(random[:], handshake[clientRandomOffset:])
	zeroed := bytes.Clone(handshake)
	for i := 0; i < clientRandomLen; i++ {
		zeroed[clientRandomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, key)
	// mtg dumps the record with version 0x0301 whatever the client sent.
	mac.Write([]byte{recordTypeHandshake, 0x03, 0x01, byte(len(zeroed) >> 8), byte(len(zeroed))})
	mac.Write(zeroed)
	computed := mac.Sum(nil)
	for i := range random {
		computed[i] ^= random[i]
	}
	return subtle.ConstantTimeCompare(computed[:clientRandomLen-4], make([]byte, clientRandomLen-4)) == 1
}

// replayConn returns the already-read ClientHello before the rest of the
// connection. RemoteAddr stays the underlying TCP address, which mtg relies on.
type replayConn struct {
	net.Conn
	buffered []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *replayConn) CloseRead() error {
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return c.Conn.Close()
}
