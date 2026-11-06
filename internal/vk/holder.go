package vk

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Holder keeps N WG-over-VK calls alive at once. Each okcdn call stays valid
// only while someone holds its owner socket, so a created-but-unheld call is
// reaped within minutes; the holder opens N owner sockets and keeps them open,
// answering the app-level ping with pong, and publishes the set of join links
// that currently have a live socket. This is the Go port of vc-holder.py.
//
// The pieces that touch the network or the pool file are interfaces, so the
// lifecycle here -- open, hold, re-open on drop, republish, back off, and ask
// for a relogin when the access token dies -- is testable without either.
type Holder struct {
	// Source opens one held call; Pub writes the live set out.
	Source CallSource
	Pub    Publisher
	// Relogin is run when the access token itself is dead (CallSource.Open
	// returned ErrAccessTokenExpired); until it returns, slots wait.
	Relogin func(ctx context.Context) error

	N         int           // how many calls to hold
	Heartbeat time.Duration // republish the live set this often (0 disables)
	Log       *slog.Logger

	// Pacing. Zero values fall back to production defaults; tests set them small.
	ReopenPause  time.Duration // pause after a drop before re-opening (default 2s)
	ReloginPause time.Duration // pause after a relogin before retrying (default 5s)

	mu       sync.Mutex
	held     map[int]string // slot -> join link, only slots with an open socket
	reloginM sync.Mutex     // one relogin at a time
}

// CallConn is an open owner socket. Hold answers pings until the socket drops
// or ctx is cancelled, then returns; Close releases it.
type CallConn interface {
	Hold(ctx context.Context) error
	Close() error
}

// CallSource mints a call and opens its owner socket. Open returns
// ErrAccessTokenExpired when the one-year access token is dead (a relogin is
// needed), ErrCallTokenExpired is handled inside Open by re-minting, and any
// other error is transient.
type CallSource interface {
	Open(ctx context.Context) (joinLink string, conn CallConn, err error)
}

// Publisher writes the live join links out (to the shared pool in production).
type Publisher interface {
	Publish(ctx context.Context, live []string) error
}

func (h *Holder) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Run holds N calls until ctx is cancelled.
func (h *Holder) Run(ctx context.Context) error {
	n := h.N
	if n < 1 {
		n = 4
	}
	h.mu.Lock()
	h.held = make(map[int]string, n)
	h.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			h.slotLoop(ctx, slot)
		}(i)
	}
	if h.Heartbeat > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.heartbeat(ctx)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

// slotLoop keeps one slot holding a call: open, hold, and on any drop open a
// fresh call. Backoff grows on repeated transient failures and resets on a
// hold that actually took.
func (h *Holder) slotLoop(ctx context.Context, slot int) {
	backoff := 5 * time.Second
	const maxBackoff = 2 * time.Minute
	for ctx.Err() == nil {
		link, conn, err := h.Source.Open(ctx)
		switch {
		case err == nil:
			// held below
		case errors.Is(err, ErrAccessTokenExpired):
			h.doRelogin(ctx)
			sleep(ctx, orDur(h.ReloginPause, 5*time.Second))
			continue
		default:
			h.log().Warn("could not open a call", "slot", slot, "error", err)
			sleep(ctx, backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = 5 * time.Second
		h.set(slot, link)
		h.publish(ctx)
		h.log().Info("holding a call", "slot", slot, "link", link)

		err = conn.Hold(ctx)
		_ = conn.Close()
		if err != nil && ctx.Err() == nil {
			h.log().Info("a held call dropped", "slot", slot, "error", err)
		}
		h.clear(slot)
		h.publish(ctx)
		sleep(ctx, orDur(h.ReopenPause, 2*time.Second)) // brief pause, then re-open
	}
}

// orDur returns d if it is positive, otherwise the fallback.
func orDur(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

// doRelogin runs the relogin once, serialised so N slots hitting a dead token
// at once do not launch N of them.
func (h *Holder) doRelogin(ctx context.Context) {
	h.reloginM.Lock()
	defer h.reloginM.Unlock()
	if h.Relogin == nil {
		h.log().Warn("access token dead and no relogin configured; waiting")
		sleep(ctx, 2*time.Minute)
		return
	}
	h.log().Info("access token dead; running relogin")
	if err := h.Relogin(ctx); err != nil && ctx.Err() == nil {
		h.log().Error("relogin failed", "error", err)
	}
}

func (h *Holder) heartbeat(ctx context.Context) {
	t := time.NewTicker(h.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Republish reasserts the live set: the bot's validator does a
			// load -> check -> save that can clobber an on-change write, and a
			// periodic republish makes any such clobber self-correct.
			if h.anyHeld() {
				h.publish(ctx)
			}
		}
	}
}

func (h *Holder) set(slot int, link string) {
	h.mu.Lock()
	h.held[slot] = link
	h.mu.Unlock()
}

func (h *Holder) clear(slot int) {
	h.mu.Lock()
	delete(h.held, slot)
	h.mu.Unlock()
}

func (h *Holder) anyHeld() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.held) > 0
}

// liveSet is the sorted, de-duplicated set of currently-held links.
func (h *Holder) liveSet() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := make(map[string]struct{}, len(h.held))
	out := make([]string, 0, len(h.held))
	for _, link := range h.held {
		if _, dup := seen[link]; dup || link == "" {
			continue
		}
		seen[link] = struct{}{}
		out = append(out, link)
	}
	sort.Strings(out)
	return out
}

func (h *Holder) publish(ctx context.Context) {
	live := h.liveSet()
	if err := h.Pub.Publish(ctx, live); err != nil {
		h.log().Warn("could not publish the live set", "error", err)
		return
	}
	h.log().Info("published live calls", "count", len(live))
}

// sleep waits d or until ctx is done, whichever comes first.
func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
