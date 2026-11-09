package reload

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type brokenMarker struct{}

func (brokenMarker) Touch(string, string) error { return errors.New("disk full") }

func TestANilLoggerFallsBackToTheDefaultOne(t *testing.T) {
	r := New(&fakeCore{}, nil, "m", nil)
	if r.log == nil {
		t.Fatal("no logger")
	}
	if err := r.Request(context.Background()); err != nil {
		t.Errorf("Request: %v", err)
	}
}

func TestAFailedRestartAtTheCloseOfABatchIsLoggedNotLost(t *testing.T) {
	// No marker: the fallback fails, and a close has nobody to return that to.
	core := &fakeCore{applyErr: errors.New("nope")}
	r := New(core, nil, "m", slog.New(slog.DiscardHandler))
	ctx, done := r.Begin(context.Background())
	if err := r.Request(ctx); err != nil {
		t.Fatalf("Request inside a batch: %v", err)
	}
	done()
	if core.count() != 1 {
		t.Errorf("applies = %d, want the single deferred one", core.count())
	}
}

func TestAMarkerThatCannotBeTouchedIsReported(t *testing.T) {
	core := &fakeCore{applyErr: errors.New("nope")}
	err := New(core, brokenMarker{}, "m", slog.New(slog.DiscardHandler)).Request(context.Background())
	if err == nil || !strings.Contains(err.Error(), "touch restart marker") {
		t.Errorf("error = %v", err)
	}
}

func TestCancellationDuringTheProbesStopsTheWait(t *testing.T) {
	restoreTimings(t, time.Millisecond, time.Hour, time.Hour)
	core := &fakeCore{applyErr: errors.New("nope"), versionErrsBefore: 1 << 30}
	r := newReloader(core, &fakeMarker{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for core.count() == 0 {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if err := r.Request(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the cancellation", err)
	}
}
