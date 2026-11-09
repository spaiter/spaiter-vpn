package reload

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type fakeCore struct {
	mu       sync.Mutex
	applies  int
	versions int
	applyErr error
	// versionErrsBefore makes Version fail this many times before answering,
	// standing in for a core that is still coming up.
	versionErrsBefore int
}

func (f *fakeCore) Apply(context.Context) (*ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	return &ApplyResult{Inbounds: Outcome{Reloaded: []string{"vless-reality-in"}}}, nil
}

func (f *fakeCore) Version(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions++
	if f.versions <= f.versionErrsBefore {
		return errors.New("not up yet")
	}
	return nil
}

func (f *fakeCore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies
}

type fakeMarker struct {
	mu      sync.Mutex
	touched []string
}

func (m *fakeMarker) Touch(name, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched = append(m.touched, name)
	return nil
}

func newReloader(core Applier, marker Marker) *Reloader {
	return New(core, marker, ".reload-singbox", slog.New(slog.DiscardHandler))
}

func TestRequestOutsideABatchAppliesAtOnce(t *testing.T) {
	core := &fakeCore{}
	r := newReloader(core, &fakeMarker{})

	if err := r.Request(context.Background()); err != nil {
		t.Fatalf("Request: %v", err)
	}
	if core.count() != 1 {
		t.Errorf("applies = %d, want 1", core.count())
	}
}

// TestBatchCollapsesManyRequests is the whole point: provisioning one user
// touches a dozen inbounds and four endpoints, and each helper used to apply
// on its own.
func TestBatchCollapsesManyRequests(t *testing.T) {
	core := &fakeCore{}
	r := newReloader(core, &fakeMarker{})

	ctx, done := r.Begin(context.Background())
	for range 6 {
		if err := r.Request(ctx); err != nil {
			t.Fatalf("Request: %v", err)
		}
	}
	if core.count() != 0 {
		t.Errorf("applied %d times inside the batch, want none until it closes", core.count())
	}
	done()
	if core.count() != 1 {
		t.Errorf("applies = %d, want exactly one for the batch", core.count())
	}
}

func TestNestedBatchesApplyOnceAtTheOutermostClose(t *testing.T) {
	core := &fakeCore{}
	r := newReloader(core, &fakeMarker{})

	outer, closeOuter := r.Begin(context.Background())
	inner, closeInner := r.Begin(outer)
	if err := r.Request(inner); err != nil {
		t.Fatalf("Request: %v", err)
	}
	closeInner()
	if core.count() != 0 {
		t.Error("the inner close applied; only the outermost should")
	}
	closeOuter()
	if core.count() != 1 {
		t.Errorf("applies = %d, want 1", core.count())
	}
}

func TestAnEmptyBatchAppliesNothing(t *testing.T) {
	core := &fakeCore{}
	r := newReloader(core, &fakeMarker{})

	_, done := r.Begin(context.Background())
	done()
	if core.count() != 0 {
		t.Errorf("applies = %d, want none: nothing asked for one", core.count())
	}
}

// TestConcurrentBatchesDoNotShareTheirFlag is why the counter lives in the
// context. With a global, the first batch to close would apply the second
// one's half-written work, and the second would then find nothing pending.
func TestConcurrentBatchesDoNotShareTheirFlag(t *testing.T) {
	core := &fakeCore{}
	r := newReloader(core, &fakeMarker{})

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, done := r.Begin(context.Background())
			if err := r.Request(ctx); err != nil {
				t.Errorf("Request: %v", err)
			}
			done()
		}()
	}
	close(start)
	wg.Wait()

	// Four independent batches, four applies: each one's work is its own.
	if got := core.count(); got != 4 {
		t.Errorf("applies = %d, want one per batch (4)", got)
	}
}

// TestApplyFailureFallsBackToTheMarker: the bot has no Docker socket, so the
// last resort is a file a privileged unit watches.
func TestApplyFailureFallsBackToTheMarker(t *testing.T) {
	restoreTimings(t, 10*time.Millisecond, 5*time.Millisecond, time.Second)

	core := &fakeCore{applyErr: errors.New("apply refused")}
	marker := &fakeMarker{}
	r := newReloader(core, marker)

	if err := r.Request(context.Background()); err != nil {
		t.Fatalf("Request: %v", err)
	}
	marker.mu.Lock()
	touched := append([]string{}, marker.touched...)
	marker.mu.Unlock()
	if len(touched) != 1 || touched[0] != ".reload-singbox" {
		t.Fatalf("markers touched = %v", touched)
	}
}

// TestRestartWaitsForTheCoreToAnswer matters because returning early would let
// the next provisioning step write into a config nobody is reading yet, and
// report success for a user who cannot connect.
func TestRestartWaitsForTheCoreToAnswer(t *testing.T) {
	restoreTimings(t, 10*time.Millisecond, 5*time.Millisecond, 2*time.Second)

	core := &fakeCore{applyErr: errors.New("nope"), versionErrsBefore: 3}
	r := newReloader(core, &fakeMarker{})

	if err := r.Request(context.Background()); err != nil {
		t.Fatalf("Request: %v", err)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.versions <= core.versionErrsBefore {
		t.Errorf("probed %d times, want more than the %d failures",
			core.versions, core.versionErrsBefore)
	}
}

func TestRestartGivesUpAndSaysSo(t *testing.T) {
	restoreTimings(t, 5*time.Millisecond, 5*time.Millisecond, 50*time.Millisecond)

	core := &fakeCore{applyErr: errors.New("nope"), versionErrsBefore: 1 << 30}
	err := newReloader(core, &fakeMarker{}).Request(context.Background())
	if err == nil {
		t.Fatal("a core that never came back was reported as fine")
	}
}

func TestRestartWithoutAMarkerIsAnError(t *testing.T) {
	core := &fakeCore{applyErr: errors.New("nope")}
	err := New(core, nil, ".reload-singbox", slog.New(slog.DiscardHandler)).
		Request(context.Background())
	if err == nil {
		t.Fatal("no marker and no apply was reported as success")
	}
}

func TestCancellationStopsTheRestartWait(t *testing.T) {
	restoreTimings(t, time.Hour, time.Second, time.Hour)

	core := &fakeCore{applyErr: errors.New("nope"), versionErrsBefore: 1 << 30}
	r := newReloader(core, &fakeMarker{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Request(ctx) }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want the cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the restart wait ignored cancellation")
	}
}

// restoreTimings shortens the restart timings for a test and puts them back
// afterwards, so the suite does not spend half a minute proving a retry loop.
func restoreTimings(t *testing.T, grace, probe, timeout time.Duration) {
	t.Helper()
	oldGrace, oldProbe, oldTimeout := RestartGrace, RestartProbeInterval, RestartTimeout
	RestartGrace, RestartProbeInterval, RestartTimeout = grace, probe, timeout
	t.Cleanup(func() {
		RestartGrace, RestartProbeInterval, RestartTimeout = oldGrace, oldProbe, oldTimeout
	})
}
