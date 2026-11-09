package loops

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func TestConstructorsFallBackToTheDefaultLogger(t *testing.T) {
	store := newStore(t)
	if NewRefresher(store, bundleFunc(func(string) ([]byte, error) { return nil, nil }), nil, nil).log == nil {
		t.Error("the refresher has no logger")
	}
	if p := NewPoolChecker(store, checkFunc(nil), nil, nil); p.log == nil || p.HolderName == "" || p.LowWaterMark != 2 {
		t.Errorf("pool checker defaults: %+v", p)
	}
}

func TestRunRefreshKeepsGoingAfterAFailedRound(t *testing.T) {
	store := newStore(t)
	issue(t, store, "42")
	var rounds atomic.Int32
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		rounds.Add(1)
		return nil, errors.New("builder is down")
	}), newNotifier(), quiet())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.RunRefresh(ctx, 5*time.Millisecond, 0, "tick") }()
	for deadline := time.Now().Add(3 * time.Second); rounds.Load() < 3 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if rounds.Load() < 3 {
		t.Errorf("the loop ran %d rounds, want it to retry after failures", rounds.Load())
	}
}

func TestRunValidateKeepsGoingAfterAFailedRoundAndStopsOnCancel(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{"h": {Status: "ok", ByName: "x", By: 1}})
	var rounds atomic.Int32
	p := newChecker(t, store, newNotifier(), func([]string) (map[string]external.HashStatus, error) {
		rounds.Add(1)
		return nil, errors.New("helper unreachable")
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.RunValidate(ctx, 5*time.Millisecond, 0) }()
	for deadline := time.Now().Add(3 * time.Second); rounds.Load() < 3 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if rounds.Load() < 3 {
		t.Errorf("ran %d rounds", rounds.Load())
	}

	// Cancelled during the settle delay: no round at all.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	before := rounds.Load()
	if err := p.RunValidate(ctx2, time.Hour, time.Hour); !errors.Is(err, context.Canceled) || rounds.Load() != before {
		t.Errorf("settle cancel: err=%v rounds %d→%d", err, before, rounds.Load())
	}
}

func TestNotifyWatchWithNoMarkerDoesNothingAndStopsOnCancel(t *testing.T) {
	store := newStore(t)
	issue(t, store, "42")
	var builds atomic.Int32
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		builds.Add(1)
		return bundleWith("relay.example"), nil
	}), newNotifier(), quiet())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := r.RunNotifyWatch(ctx, ".absent", 5*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if builds.Load() != 0 {
		t.Errorf("a refresh ran %d times with no marker", builds.Load())
	}
}

func TestPoolAlarmsReachTheRightPeopleAndSurviveDeliveryFailures(t *testing.T) {
	check := func([]string) (map[string]external.HashStatus, error) {
		return map[string]external.HashStatus{"a": {Status: "dead"}, "b": {Status: "dead"}, "holder": {Status: "dead"}}, nil
	}
	pool := state.VKHashes{
		"a":      {Status: "ok", ByName: "person", By: 7},
		"b":      {Status: "ok", ByName: "admin", By: 99},
		"holder": {Status: "ok", ByName: "vkcalls-server"},
	}

	// An admin is told as an admin only; a holder's link dying is routine and silent.
	store := newStore(t)
	seedPool(t, store, pool)
	if err := store.AddAdmin(99); err != nil {
		t.Fatal(err)
	}
	notifier := newNotifier()
	p := newChecker(t, store, notifier, check)
	if _, err := p.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notifier.told("7") != 1 || notifier.told("99") != 0 {
		t.Errorf("owner messages: 7→%d 99→%d", notifier.told("7"), notifier.told("99"))
	}
	if len(notifier.admin) < 1 {
		t.Fatal("no admin alarm")
	}
	for _, text := range notifier.admin {
		if text == "dead: [holder]" {
			t.Errorf("the holder's own link was announced: %q", text)
		}
	}

	// Delivery failures are logged, not fatal, and a nil notifier is silent.
	store2 := newStore(t)
	seedPool(t, store2, pool)
	failing := newNotifier()
	failing.err = errors.New("telegram is down")
	if _, err := newChecker(t, store2, failing, check).Validate(context.Background()); err != nil {
		t.Errorf("a failed delivery failed the validation: %v", err)
	}
	store3 := newStore(t)
	seedPool(t, store3, pool)
	if _, err := newChecker(t, store3, nil, check).Validate(context.Background()); err != nil {
		t.Errorf("no notifier: %v", err)
	}

	// Without message texts nothing is sent.
	store4 := newStore(t)
	seedPool(t, store4, pool)
	quietNotifier := newNotifier()
	bare := NewPoolChecker(store4, checkFunc(check), quietNotifier, quiet())
	if _, err := bare.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(quietNotifier.admin) != 0 || len(quietNotifier.direct) != 0 {
		t.Errorf("messages were sent without texts: %+v %+v", quietNotifier.admin, quietNotifier.direct)
	}
}

func TestAnnounceMoveSkipsWhatItCannotDeliver(t *testing.T) {
	links := func(string) (string, string) { return "cf", "direct" }
	text := func(cf, direct string) string { return cf + direct }
	ctx := context.Background()

	// Without a notifier the new base is recorded and nobody is told.
	store := newStore(t)
	issue(t, store, "1")
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) { return nil, nil }), nil, quiet())
	r.AnnounceMove(ctx, state.SubscriptionBase{HostDirect: "a"}, links, text)
	if n, err := r.AnnounceMove(ctx, state.SubscriptionBase{HostDirect: "b"}, links, text); err != nil || n != 0 {
		t.Errorf("no notifier: %d %v", n, err)
	}
	if base, found, _ := store.SubscriptionBase(); !found || base.HostDirect != "b" {
		t.Errorf("base = %+v %v", base, found)
	}

	// An empty current base is recorded, not announced.
	store2 := newStore(t)
	issue(t, store2, "1")
	n2 := newNotifier()
	r2 := NewRefresher(store2, bundleFunc(func(string) ([]byte, error) { return nil, nil }), n2, quiet())
	r2.AnnounceMove(ctx, state.SubscriptionBase{HostDirect: "a"}, links, text)
	if n, err := r2.AnnounceMove(ctx, state.SubscriptionBase{}, links, text); err != nil || n != 0 || len(n2.direct) != 0 {
		t.Errorf("empty base: %d %v %v", n, err, n2.direct)
	}

	// A subscriber who cannot be reached is skipped and the base is still recorded.
	store3 := newStore(t)
	issue(t, store3, "1")
	n3 := newNotifier()
	r3 := NewRefresher(store3, bundleFunc(func(string) ([]byte, error) { return nil, nil }), n3, quiet())
	r3.AnnounceMove(ctx, state.SubscriptionBase{HostDirect: "a"}, links, text)
	n3.err = errors.New("blocked the bot")
	if n, err := r3.AnnounceMove(ctx, state.SubscriptionBase{HostDirect: "b"}, links, text); err != nil || n != 0 {
		t.Errorf("unreachable: %d %v", n, err)
	}
	if base, _, _ := store3.SubscriptionBase(); base.HostDirect != "b" {
		t.Errorf("base = %+v, want the move recorded despite the failure", base)
	}

	// Cancellation stops the loop and reports it.
	store4 := newStore(t)
	issue(t, store4, "1")
	r4 := NewRefresher(store4, bundleFunc(func(string) ([]byte, error) { return nil, nil }), newNotifier(), quiet())
	r4.AnnounceMove(ctx, state.SubscriptionBase{HostDirect: "a"}, links, text)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r4.AnnounceMove(cancelled, state.SubscriptionBase{HostDirect: "b"}, links, text); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}
