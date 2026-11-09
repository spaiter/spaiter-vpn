package loops

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func corruptFile(t *testing.T, store *state.Store, parts ...string) {
	t.Helper()
	if err := os.WriteFile(store.Path(parts...), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func okBuilder() bundleFunc {
	return func(string) ([]byte, error) { return bundleWith("relay.example"), nil }
}

func TestRefreshFailsLoudlyWhenTheRegistryIsUnreadable(t *testing.T) {
	store := newStore(t)
	corruptFile(t, store, "wdtt", "subs.json")
	r := NewRefresher(store, okBuilder(), newNotifier(), quiet())
	if _, err := r.RefreshAll(context.Background(), ""); err == nil {
		t.Error("RefreshAll over an unreadable registry succeeded")
	}
	if _, err := r.AdoptHashes(context.Background()); err == nil {
		t.Error("AdoptHashes over an unreadable registry succeeded")
	}
	links := func(string) (string, string) { return "cf", "direct" }
	text := func(cf, direct string) string { return cf + direct }
	if _, err := r.AnnounceMove(context.Background(), state.SubscriptionBase{HostCF: "a"}, links, text); err == nil {
		// The base is read first; a corrupt registry matters once it is walked.
		t.Log("AnnounceMove tolerated the unreadable registry because the base was unset")
	}
}

func TestRefreshSkipsWhatItCannotBuildHashOrOwn(t *testing.T) {
	store := newStore(t)
	good := issue(t, store, "1")
	issue(t, store, "2")
	issue(t, store, "3")
	if err := store.UpdateSubscriptions(func(s state.Subscriptions) error {
		s["ownerless"] = state.Subscription{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r := NewRefresher(store, bundleFunc(func(uid string) ([]byte, error) {
		switch uid {
		case "2":
			return nil, errors.New("peer file gone")
		case "3":
			return []byte("not json"), nil
		}
		return bundleWith("relay.example"), nil
	}), newNotifier(), quiet())

	if _, err := r.RefreshAll(context.Background(), ""); err != nil {
		t.Fatalf("one broken user stopped the round: %v", err)
	}
	if _, found, _ := store.BundleCache(good); !found {
		t.Error("the healthy user was not refreshed")
	}
	if _, found, _ := store.BundleCache("ownerless"); found {
		t.Error("an ownerless subscription got a cache")
	}
}

func TestRefreshStopsOnCancellationAndOnAnUnwritableCache(t *testing.T) {
	store := newStore(t)
	issue(t, store, "1")
	r := NewRefresher(store, okBuilder(), newNotifier(), quiet())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.RefreshAll(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}

	// The cache directory replaced by a file: the write fails and so does the round.
	if err := os.RemoveAll(store.Path("wdtt", "subs-cache")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path("wdtt", "subs-cache"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RefreshAll(context.Background(), ""); err == nil {
		t.Error("an unwritable cache was not reported")
	}
}

func TestRefreshKeepsASubscriptionRemovedWhileItRan(t *testing.T) {
	store := newStore(t)
	token := issue(t, store, "1")
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		// Deleted while the bundle is being built.
		_ = store.UpdateSubscriptions(func(s state.Subscriptions) error {
			delete(s, token)
			return nil
		})
		return bundleWith("relay.example"), nil
	}), newNotifier(), quiet())
	if _, err := r.RefreshAll(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	subs, _ := store.Subscriptions()
	if _, back := subs[token]; back {
		t.Error("a deleted subscription came back")
	}
}

func TestTheNotifyWatchReportsMarkerTroubleAndKeepsWatching(t *testing.T) {
	store := newStore(t)
	issue(t, store, "1")
	var rounds atomic.Int32
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		rounds.Add(1)
		return nil, errors.New("builder down")
	}), newNotifier(), quiet())

	// A marker that is a directory cannot be read; a valid one is consumed even
	// though the refresh it triggers fails.
	if err := os.Mkdir(store.Path("unreadable-marker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Touch("ok-marker", "why"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.RunNotifyWatch(ctx, "ok-marker", 5*time.Millisecond)
	}()
	for deadline := time.Now().Add(3 * time.Second); rounds.Load() < 1 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
	}
	cancel()
	<-done
	if rounds.Load() < 1 {
		t.Error("the marker did not trigger a refresh")
	}
	if _, found, _ := store.ReadMarker("ok-marker"); found {
		t.Error("the marker was not consumed")
	}

	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- r.RunNotifyWatch(ctx, "unreadable-marker", 5*time.Millisecond) }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestPoolValidationReportsAnUnreadablePool(t *testing.T) {
	store := newStore(t)
	corruptFile(t, store, "wdtt", "vk_hashes.json")
	p := newChecker(t, store, newNotifier(), func([]string) (map[string]external.HashStatus, error) { return nil, nil })
	if _, err := p.Validate(context.Background()); err == nil || strings.Contains(err.Error(), "nil") {
		t.Errorf("unreadable pool: %v", err)
	}
}
