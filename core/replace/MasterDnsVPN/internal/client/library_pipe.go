// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client: an in-memory connection between a stream's ARQ and the program
// that embeds the client (library.go). It is a net.Pipe with a buffer: the ARQ
// gives up on a local write after a few 500 ms timeouts, and a net.Pipe write
// blocks until the other side reads, so a slow application would reset its
// streams. Here a write is accepted as long as the buffer is below its limit.
// ==============================================================================

package client

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// LibraryPipeBufferLimit is the most bytes one direction of a library stream holds before a
// write waits for the reader.
var LibraryPipeBufferLimit = 4 * 1024 * 1024

// pipeDirection carries bytes one way, from one end's Write to the other end's Read.
type pipeDirection struct {
	mu            sync.Mutex
	cond          *sync.Cond
	buf           bytes.Buffer
	writerClosed  bool // the writing end closed: Read returns EOF once the buffer is empty
	readerClosed  bool // the reading end closed: Write fails
	readDeadline  pipeDeadline
	writeDeadline pipeDeadline
	limit         int
}

func newPipeDirection(limit int) *pipeDirection {
	d := &pipeDirection{limit: limit}
	d.cond = sync.NewCond(&d.mu)
	d.readDeadline.init(d.cond)
	d.writeDeadline.init(d.cond)
	return d
}

func (d *pipeDirection) read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		if d.readerClosed {
			return 0, io.ErrClosedPipe
		}
		if d.buf.Len() > 0 {
			n, _ := d.buf.Read(p)
			if d.buf.Len() == 0 {
				d.buf.Reset()
			}
			d.cond.Broadcast()
			return n, nil
		}
		if d.writerClosed {
			return 0, io.EOF
		}
		if d.readDeadline.expired() {
			return 0, os.ErrDeadlineExceeded
		}
		if len(p) == 0 {
			return 0, nil
		}
		d.cond.Wait()
	}
}

func (d *pipeDirection) write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		if d.writerClosed || d.readerClosed {
			return 0, io.ErrClosedPipe
		}
		if d.buf.Len() < d.limit || len(p) == 0 {
			d.buf.Write(p)
			d.cond.Broadcast()
			return len(p), nil
		}
		if d.writeDeadline.expired() {
			return 0, os.ErrDeadlineExceeded
		}
		d.cond.Wait()
	}
}

func (d *pipeDirection) closeWriter() {
	d.mu.Lock()
	d.writerClosed = true
	d.cond.Broadcast()
	d.mu.Unlock()
}

func (d *pipeDirection) closeReader() {
	d.mu.Lock()
	d.readerClosed = true
	d.buf.Reset()
	d.cond.Broadcast()
	d.mu.Unlock()
}

// pipeDeadline wakes the waiters of a direction when its time comes. It is used with the
// direction's lock held.
type pipeDeadline struct {
	cond  *sync.Cond
	at    time.Time
	timer *time.Timer
}

func (pd *pipeDeadline) init(cond *sync.Cond) { pd.cond = cond }

func (pd *pipeDeadline) set(t time.Time) {
	if pd.timer != nil {
		pd.timer.Stop()
		pd.timer = nil
	}
	pd.at = t
	if t.IsZero() {
		return
	}
	wait := time.Until(t)
	if wait <= 0 {
		pd.cond.Broadcast()
		return
	}
	cond := pd.cond
	pd.timer = time.AfterFunc(wait, func() {
		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()
	})
}

func (pd *pipeDeadline) expired() bool {
	return !pd.at.IsZero() && !time.Now().Before(pd.at)
}

// libraryPipeConn is one end of the connection: it reads from one direction and writes to the
// other.
type libraryPipeConn struct {
	rd        *pipeDirection
	wr        *pipeDirection
	closeOnce sync.Once
}

// newLibraryPipe returns the two ends of a buffered duplex connection.
func newLibraryPipe() (*libraryPipeConn, *libraryPipeConn) {
	a := newPipeDirection(LibraryPipeBufferLimit)
	b := newPipeDirection(LibraryPipeBufferLimit)
	return &libraryPipeConn{rd: a, wr: b}, &libraryPipeConn{rd: b, wr: a}
}

func (c *libraryPipeConn) Read(p []byte) (int, error)  { return c.rd.read(p) }
func (c *libraryPipeConn) Write(p []byte) (int, error) { return c.wr.write(p) }

// Close ends both directions for this end: the peer reads what is buffered and then EOF, and its
// writes fail.
func (c *libraryPipeConn) Close() error {
	c.closeOnce.Do(func() {
		c.wr.closeWriter()
		c.rd.closeReader()
	})
	return nil
}

func (c *libraryPipeConn) LocalAddr() net.Addr  { return libraryPipeAddr{} }
func (c *libraryPipeConn) RemoteAddr() net.Addr { return libraryPipeAddr{} }

func (c *libraryPipeConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *libraryPipeConn) SetReadDeadline(t time.Time) error {
	c.rd.mu.Lock()
	c.rd.readDeadline.set(t)
	c.rd.mu.Unlock()
	return nil
}

func (c *libraryPipeConn) SetWriteDeadline(t time.Time) error {
	c.wr.mu.Lock()
	c.wr.writeDeadline.set(t)
	c.wr.mu.Unlock()
	return nil
}

type libraryPipeAddr struct{}

func (libraryPipeAddr) Network() string { return "masterdns" }
func (libraryPipeAddr) String() string  { return "masterdns" }
