package bufio

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The cached buffer is guarded by access: Close can run on another goroutine
// while Read or WriteTo is draining it, and both used to release it.
type CachedConn struct {
	net.Conn
	access sync.Mutex
	buffer *buf.Buffer
}

func NewCachedConn(conn net.Conn, buffer *buf.Buffer) *CachedConn {
	buffer.IncRef()
	return &CachedConn{
		Conn:   conn,
		buffer: buffer,
	}
}

func (c *CachedConn) takeBuffer() *buf.Buffer {
	c.access.Lock()
	buffer := c.buffer
	c.buffer = nil
	c.access.Unlock()
	if buffer != nil {
		buffer.DecRef()
	}
	return buffer
}

func (c *CachedConn) ReadCached() *buf.Buffer {
	return c.takeBuffer()
}

func (c *CachedConn) Read(p []byte) (n int, err error) {
	c.access.Lock()
	if c.buffer != nil {
		n, err = c.buffer.Read(p)
		if err == nil {
			c.access.Unlock()
			return
		}
		c.buffer.DecRef()
		c.buffer.Release()
		c.buffer = nil
	}
	c.access.Unlock()
	return c.Conn.Read(p)
}

func (c *CachedConn) WriteTo(w io.Writer) (n int64, err error) {
	if buffer := c.takeBuffer(); buffer != nil {
		wn, wErr := w.Write(buffer.Bytes())
		buffer.Release()
		n += int64(wn)
		if wErr != nil {
			return n, wErr
		}
	}
	cn, err := Copy(w, c.Conn)
	n += cn
	return
}

func (c *CachedConn) ReadFrom(r io.Reader) (n int64, err error) {
	return Copy(c.Conn, r)
}

func (c *CachedConn) Upstream() any {
	return c.Conn
}

func (c *CachedConn) ReaderReplaceable() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.buffer == nil
}

func (c *CachedConn) WriterReplaceable() bool {
	return true
}

func (c *CachedConn) Close() error {
	c.takeBuffer().Release()
	return c.Conn.Close()
}

type CachedReader struct {
	upstream io.Reader
	access   sync.Mutex
	buffer   *buf.Buffer
}

func NewCachedReader(upstream io.Reader, buffer *buf.Buffer) *CachedReader {
	buffer.IncRef()
	return &CachedReader{
		upstream: upstream,
		buffer:   buffer,
	}
}

func (r *CachedReader) takeBuffer() *buf.Buffer {
	r.access.Lock()
	buffer := r.buffer
	r.buffer = nil
	r.access.Unlock()
	if buffer != nil {
		buffer.DecRef()
	}
	return buffer
}

func (r *CachedReader) ReadCached() *buf.Buffer {
	return r.takeBuffer()
}

func (r *CachedReader) Read(p []byte) (n int, err error) {
	r.access.Lock()
	if r.buffer != nil {
		n, err = r.buffer.Read(p)
		if err == nil {
			r.access.Unlock()
			return
		}
		r.buffer.DecRef()
		r.buffer.Release()
		r.buffer = nil
	}
	r.access.Unlock()
	return r.upstream.Read(p)
}

func (r *CachedReader) WriteTo(w io.Writer) (n int64, err error) {
	if buffer := r.takeBuffer(); buffer != nil {
		wn, wErr := w.Write(buffer.Bytes())
		buffer.Release()
		n += int64(wn)
		if wErr != nil {
			return n, wErr
		}
	}
	cn, err := Copy(w, r.upstream)
	n += cn
	return
}

func (r *CachedReader) Upstream() any {
	return r.upstream
}

func (r *CachedReader) ReaderReplaceable() bool {
	r.access.Lock()
	defer r.access.Unlock()
	return r.buffer == nil
}

func (r *CachedReader) Close() error {
	r.takeBuffer().Release()
	return nil
}

type CachedPacketConn struct {
	N.PacketConn
	taken       atomic.Bool
	buffer      *buf.Buffer
	destination M.Socksaddr
}

func NewCachedPacketConn(conn N.PacketConn, buffer *buf.Buffer, destination M.Socksaddr) *CachedPacketConn {
	buffer.IncRef()
	return &CachedPacketConn{
		PacketConn:  conn,
		buffer:      buffer,
		destination: destination,
	}
}

func (c *CachedPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	packet := c.ReadCachedPacket()
	if packet != nil {
		defer packet.Buffer.Release()
		defer N.PutPacketBuffer(packet)
		_, err = buffer.Write(packet.Buffer.Bytes())
		return packet.Destination, err
	}
	return c.PacketConn.ReadPacket(buffer)
}

func (c *CachedPacketConn) ReadCachedPacket() *N.PacketBuffer {
	if !c.taken.CompareAndSwap(false, true) {
		return nil
	}
	buffer := c.buffer
	c.buffer = nil
	if buffer == nil {
		return nil
	}
	buffer.DecRef()
	packet := N.NewPacketBuffer()
	*packet = N.PacketBuffer{
		Buffer:      buffer,
		Destination: c.destination,
	}
	return packet
}

func (c *CachedPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *CachedPacketConn) ReaderReplaceable() bool {
	return c.taken.Load()
}

func (c *CachedPacketConn) WriterReplaceable() bool {
	return true
}

func (c *CachedPacketConn) Close() error {
	if c.taken.CompareAndSwap(false, true) {
		if buffer := c.buffer; buffer != nil {
			c.buffer = nil
			buffer.DecRef()
			buffer.Release()
		}
	}
	return c.PacketConn.Close()
}
