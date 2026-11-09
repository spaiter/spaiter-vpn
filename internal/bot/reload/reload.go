// Package reload asks the core to apply configuration the bot has written.
//
// Provisioning one user touches a dozen inbounds and four WireGuard endpoints
// through as many helpers, each of which used to apply on its own: six round
// trips for one button press. Batch collapses them into one apply at the end.
//
// The nesting counter lives in the context rather than in a global. Two users
// being provisioned at once must not swallow each other's pending flag, and a
// global would let the first one to finish apply the second one's half-written
// work.
package reload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Applier is the part of the core's API this package needs.
type Applier interface {
	Apply(ctx context.Context) (*ApplyResult, error)
	Version(ctx context.Context) error
}

// ApplyResult is what the core reports it did, kept here so this package does
// not depend on the client package and the client does not depend on this one.
type ApplyResult struct {
	Inbounds  Outcome
	Endpoints Outcome
}

// Outcome is the per-kind breakdown. Which list a tag lands in is the
// interesting part: a tag under Reloaded kept its live connections, one under
// Recreated dropped only its own.
type Outcome struct {
	Reloaded  []string
	Recreated []string
	Added     []string
	Removed   []string
}

// Marker is the fallback path: the bot has no Docker socket by design, so it
// touches a file and something privileged restarts the core.
type Marker interface {
	Touch(name, content string) error
}

// Reloader applies configuration, batching nested requests.
type Reloader struct {
	core   Applier
	marker Marker
	// MarkerName is the file touched when apply fails.
	markerName string
	log        *slog.Logger
}

// New builds a reloader.
func New(core Applier, marker Marker, markerName string, log *slog.Logger) *Reloader {
	if log == nil {
		log = slog.Default()
	}
	return &Reloader{core: core, marker: marker, markerName: markerName, log: log}
}

// batch is the per-context state: how deep the nesting is and whether anyone
// asked for an apply while inside it.
type batch struct {
	mu      sync.Mutex
	depth   int
	pending bool
}

type batchKey struct{}

// Begin opens a batch and returns the context to use inside it along with the
// function that closes it. Nested Begins share the batch and only the outermost
// close applies.
//
//	ctx, done := r.Begin(ctx)
//	defer done()
func (r *Reloader) Begin(ctx context.Context) (context.Context, func()) {
	b, ok := ctx.Value(batchKey{}).(*batch)
	if !ok {
		b = &batch{}
		ctx = context.WithValue(ctx, batchKey{}, b)
	}

	b.mu.Lock()
	b.depth++
	b.mu.Unlock()

	// The context is captured so the close uses the same one it was opened
	// with, which is what keeps two concurrent batches apart.
	closeCtx := ctx
	return ctx, func() {
		b.mu.Lock()
		b.depth--
		shouldApply := b.depth == 0 && b.pending
		if shouldApply {
			b.pending = false
		}
		b.mu.Unlock()

		if shouldApply {
			if err := r.apply(closeCtx); err != nil {
				r.log.Error("applying configuration failed", "error", err)
			}
		}
	}
}

// Request asks for an apply. Inside a batch it only raises the flag; the
// outermost close performs the single apply.
func (r *Reloader) Request(ctx context.Context) error {
	if b, ok := ctx.Value(batchKey{}).(*batch); ok {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.depth > 0 {
			b.pending = true
			return nil
		}
	}
	return r.apply(ctx)
}

// apply diffs the config file against what is live.
//
// The core swaps a grown user list on the running inbound and programs
// WireGuard peers incrementally, so existing connections and tunnels survive.
// An inbound it cannot update that way is rebuilt on its own, which drops only
// its sessions.
func (r *Reloader) apply(ctx context.Context) error {
	result, err := r.core.Apply(ctx)
	if err == nil {
		r.log.Info("core applied configuration",
			"inbounds_reloaded", result.Inbounds.Reloaded,
			"inbounds_recreated", result.Inbounds.Recreated,
			"endpoints_added", result.Endpoints.Added)
		return nil
	}

	r.log.Warn("apply failed, falling back to a restart", "error", err)
	return r.restart(ctx)
}

// restart is the last resort: touch the marker a host unit watches, then wait
// for the API to answer again.
//
// The wait matters. Returning before the core is back would have the next
// provisioning step write into a config nobody is reading yet and report
// success for a user who cannot connect.
func (r *Reloader) restart(ctx context.Context) error {
	if r.marker == nil {
		return errors.New("reload: apply failed and no restart marker is configured")
	}
	if err := r.marker.Touch(r.markerName, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("reload: touch restart marker: %w", err)
	}

	// Let the path unit fire and the core begin stopping before probing, or
	// the first probe answers from the instance that is about to die.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(RestartGrace):
	}

	deadline := time.Now().Add(RestartTimeout)
	for time.Now().Before(deadline) {
		if err := r.core.Version(ctx); err == nil {
			r.log.Info("core came back after a restart")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(RestartProbeInterval):
		}
	}
	return fmt.Errorf("reload: core did not answer within %s of the restart marker", RestartTimeout)
}

// Timings of the restart fallback, named so a test can reason about them
// rather than guess.
var (
	// RestartGrace is how long the host unit is given to notice the marker.
	RestartGrace = 4 * time.Second
	// RestartProbeInterval is how often the API is probed afterwards.
	RestartProbeInterval = time.Second
	// RestartTimeout is how long the core has to come back.
	RestartTimeout = 25 * time.Second
)
