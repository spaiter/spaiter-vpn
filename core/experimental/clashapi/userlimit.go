package clashapi

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/option"

	"golang.org/x/time/rate"
)

// Per-user bandwidth caps.
//
// The limiter sits in Server.RoutedConnection, the same chokepoint that already
// attributes bytes to a user, so a cap follows the user across every inbound
// and every source address instead of being pinned to one protocol or IP.
//
// Two properties of sing's copy path dictate the shape of this code:
//
//   - N.UnwrapCountWriter walks down a connection's wrappers for as long as
//     each one reports WriterReplaceable() == true, collecting their counters
//     as plain callbacks, and stops at the first syscall.Conn. That is how the
//     tracker's byte counters survive splice: the copy runs between the raw
//     sockets and merely calls the counters. A blocking wrapper that reported
//     itself replaceable would be unwrapped and silently bypassed the same
//     way, so limitedConn reports false in both directions. The cost is that a
//     throttled connection loses the splice fast path — which is the point: a
//     capped user is not meant to go at zero-copy speed. Users without a cap
//     are handed back their connection untouched and keep splice.
//
//   - The wrapper has to be outermost for that stop to mean anything, so
//     RoutedConnection wraps the tracker rather than the other way round.
const (
	// burstDivisor spends a burst of one burstDivisor-th of a second's worth of
	// bytes. Smaller makes the cap tighter but stalls on every buffer; larger
	// lets a download outrun the cap in short bumps.
	burstDivisor = 8
	// minBurst keeps the burst above a typical relay buffer so that a single
	// write does not have to be split into very many waits.
	minBurst = 64 * 1024
)

// userLimit is one user's pair of token buckets. A nil pointer means unlimited
// in that direction; the pointers are swapped atomically so that a cap can be
// added, changed or removed while connections are mid-copy.
type userLimit struct {
	download atomic.Pointer[rate.Limiter]
	upload   atomic.Pointer[rate.Limiter]
}

type userLimitRegistry struct {
	access sync.RWMutex
	limits map[string]*userLimit
}

func newUserLimitRegistry(options map[string]option.UserLimitOptions) *userLimitRegistry {
	r := &userLimitRegistry{limits: make(map[string]*userLimit)}
	for user, limit := range options {
		r.Set(user, limit)
	}
	return r
}

func newLimiter(mbps float64) *rate.Limiter {
	if mbps <= 0 {
		return nil
	}
	bytesPerSecond := mbps * 1000 * 1000 / 8
	burst := int(bytesPerSecond / burstDivisor)
	if burst < minBurst {
		burst = minBurst
	}
	return rate.NewLimiter(rate.Limit(bytesPerSecond), burst)
}

// retune changes an existing bucket's rate in place rather than replacing it,
// so a connection already blocked in WaitN wakes up on the new rate instead of
// finishing at the old one.
func retune(current *atomic.Pointer[rate.Limiter], mbps float64) {
	next := newLimiter(mbps)
	existing := current.Load()
	if existing == nil || next == nil {
		current.Store(next)
		return
	}
	existing.SetLimit(next.Limit())
	existing.SetBurst(next.Burst())
}

// Set installs or updates a user's caps. An entry with both directions zero is
// removed, so "no entry" and "no cap" are the same state.
func (r *userLimitRegistry) Set(user string, options option.UserLimitOptions) {
	if options.DownloadMbps <= 0 && options.UploadMbps <= 0 {
		r.Delete(user)
		return
	}
	r.access.Lock()
	limit, exists := r.limits[user]
	if !exists {
		limit = new(userLimit)
		r.limits[user] = limit
	}
	r.access.Unlock()
	retune(&limit.download, options.DownloadMbps)
	retune(&limit.upload, options.UploadMbps)
}

func (r *userLimitRegistry) Delete(user string) {
	r.access.Lock()
	limit, exists := r.limits[user]
	delete(r.limits, user)
	r.access.Unlock()
	// Connections already wrapped keep their pointer to limit, so clearing the
	// buckets is what actually lifts the cap for them.
	if exists {
		limit.download.Store(nil)
		limit.upload.Store(nil)
	}
}

func (r *userLimitRegistry) All() map[string]option.UserLimitOptions {
	r.access.RLock()
	defer r.access.RUnlock()
	all := make(map[string]option.UserLimitOptions, len(r.limits))
	for user, limit := range r.limits {
		all[user] = option.UserLimitOptions{
			DownloadMbps: toMbps(limit.download.Load()),
			UploadMbps:   toMbps(limit.upload.Load()),
		}
	}
	return all
}

func toMbps(limiter *rate.Limiter) float64 {
	if limiter == nil {
		return 0
	}
	return float64(limiter.Limit()) * 8 / 1000 / 1000
}

func (r *userLimitRegistry) lookup(user string) *userLimit {
	if user == "" {
		return nil
	}
	r.access.RLock()
	defer r.access.RUnlock()
	return r.limits[user]
}

// WrapConn returns conn unchanged for a user with no cap, which is both the
// common case and the one where the splice fast path matters.
func (r *userLimitRegistry) WrapConn(ctx context.Context, user string, conn net.Conn) net.Conn {
	limit := r.lookup(user)
	if limit == nil {
		return conn
	}
	return &limitedConn{ExtendedConn: bufio.NewExtendedConn(conn), ctx: ctx, limit: limit}
}

func (r *userLimitRegistry) WrapPacketConn(ctx context.Context, user string, conn N.PacketConn) N.PacketConn {
	limit := r.lookup(user)
	if limit == nil {
		return conn
	}
	return &limitedPacketConn{PacketConn: conn, ctx: ctx, limit: limit}
}

// wait spends n bytes of budget, in chunks no larger than the burst. WaitN
// refuses outright when n exceeds the burst, and buffer sizes are not ours to
// choose, so chunking is what keeps a large write from failing instead of
// slowing down.
func wait(ctx context.Context, limiter *rate.Limiter, n int) error {
	if limiter == nil || n <= 0 {
		return nil
	}
	for n > 0 {
		chunk := n
		if burst := limiter.Burst(); chunk > burst {
			chunk = burst
		}
		err := limiter.WaitN(ctx, chunk)
		if err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

type limitedConn struct {
	N.ExtendedConn
	ctx   context.Context
	limit *userLimit
}

// Reads are throttled after the fact: bytes already in hand cannot be
// un-read, so the budget is spent before the caller gets them back and the
// delay lands on the next read instead.
func (c *limitedConn) Read(p []byte) (int, error) {
	n, err := c.ExtendedConn.Read(p)
	if n > 0 {
		waitErr := wait(c.ctx, c.limit.upload.Load(), n)
		if waitErr != nil && err == nil {
			return n, waitErr
		}
	}
	return n, err
}

func (c *limitedConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.ExtendedConn.ReadBuffer(buffer)
	if err != nil {
		return err
	}
	return wait(c.ctx, c.limit.upload.Load(), buffer.Len())
}

func (c *limitedConn) Write(p []byte) (int, error) {
	err := wait(c.ctx, c.limit.download.Load(), len(p))
	if err != nil {
		return 0, err
	}
	return c.ExtendedConn.Write(p)
}

func (c *limitedConn) WriteBuffer(buffer *buf.Buffer) error {
	err := wait(c.ctx, c.limit.download.Load(), buffer.Len())
	if err != nil {
		buffer.Release()
		return err
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *limitedConn) Upstream() any {
	return c.ExtendedConn
}

// False in both directions: see the note at the top of this file. Reporting
// true here would let sing unwrap past the limiter and splice around it.
func (c *limitedConn) ReaderReplaceable() bool {
	return false
}

func (c *limitedConn) WriterReplaceable() bool {
	return false
}

type limitedPacketConn struct {
	N.PacketConn
	ctx   context.Context
	limit *userLimit
}

func (c *limitedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	return destination, wait(c.ctx, c.limit.upload.Load(), buffer.Len())
}

func (c *limitedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := wait(c.ctx, c.limit.download.Load(), buffer.Len())
	if err != nil {
		buffer.Release()
		return err
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *limitedPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *limitedPacketConn) ReaderReplaceable() bool {
	return false
}

func (c *limitedPacketConn) WriterReplaceable() bool {
	return false
}
