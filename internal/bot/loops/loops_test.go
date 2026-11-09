package loops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// bundleFunc renders whatever a test wants for a uid.
type bundleFunc func(uid string) ([]byte, error)

func (f bundleFunc) Bundle(_ context.Context, uid string) ([]byte, error) { return f(uid) }

// bundleWith renders a bundle whose only interesting part is one outbound, so a
// test can change it and see whether the change is noticed.
func bundleWith(server string, vkHashes ...string) []byte {
	outbound := map[string]any{
		"type": "wdtt", "tag": "vk", "server": server, "server_port": 10865,
	}
	if len(vkHashes) > 0 {
		outbound["vk_hashes"] = vkHashes
	}
	encoded, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
	if err != nil {
		panic(err)
	}
	return encoded
}

type recordingNotifier struct {
	mu     sync.Mutex
	direct map[string][]string
	admin  []string
	err    error
}

func newNotifier() *recordingNotifier {
	return &recordingNotifier{direct: map[string][]string{}}
}

func (n *recordingNotifier) Notify(_ context.Context, uid, text string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.direct[uid] = append(n.direct[uid], text)
	return nil
}

func (n *recordingNotifier) NotifyAdmins(_ context.Context, text string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.admin = append(n.admin, text)
	return nil
}

func (n *recordingNotifier) told(uid string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.direct[uid])
}

func newStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return store
}

// issue creates a subscription the way the bot does.
func issue(t *testing.T, store *state.Store, uid string) string {
	t.Helper()
	token, err := store.SubscriptionToken(uid)
	if err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}
	return token
}

// TestFirstRefreshIsSilent: a token seen for the first time has no recorded
// hash, and announcing a change on first sight would message every subscriber
// each time the bot restarted.
func TestFirstRefreshIsSilent(t *testing.T) {
	store := newStore(t)
	token := issue(t, store, "42")
	notifier := newNotifier()
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith("relay.example"), nil
	}), notifier, quiet())

	notified, err := r.RefreshAll(context.Background(), "")
	if err != nil {
		t.Fatalf("RefreshAll: %v", err)
	}
	if notified != 0 {
		t.Errorf("notified %d subscribers on first sight", notified)
	}

	// The cache is written all the same -- that is what the client reads.
	cached, found, err := store.BundleCache(token)
	if err != nil || !found {
		t.Fatalf("bundle cache: found=%v err=%v", found, err)
	}
	if len(cached) == 0 {
		t.Error("the cache is empty")
	}
	// And the hash is recorded, so the next change is noticed.
	subs, _ := store.Subscriptions()
	if subs[token].LastHash == "" {
		t.Error("no hash was recorded, so the next change would be silent too")
	}
}

func TestRefreshNoticesAChangedBundle(t *testing.T) {
	store := newStore(t)
	issue(t, store, "42")
	notifier := newNotifier()
	server := "relay.example"
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith(server), nil
	}), notifier, quiet())
	r.ChangedText = func(reason string) string { return "changed: " + reason }

	if _, err := r.RefreshAll(context.Background(), "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	server = "relay2.example" // the DS-Lite port moved, say
	notified, err := r.RefreshAll(context.Background(), "порт сменился")
	if err != nil {
		t.Fatalf("RefreshAll: %v", err)
	}
	if notified != 1 {
		t.Fatalf("notified = %d, want 1", notified)
	}
	if got := notifier.direct["42"]; len(got) != 1 || got[0] != "changed: порт сменился" {
		t.Errorf("message = %v, want the reason passed through", got)
	}

	// And it settles: an unchanged bundle is not announced again.
	notified, err = r.RefreshAll(context.Background(), "again")
	if err != nil {
		t.Fatalf("third RefreshAll: %v", err)
	}
	if notified != 0 {
		t.Errorf("notified = %d on an unchanged bundle", notified)
	}
}

// TestRotatedVKLinksAreNotAChange is the point of the structural hash: the
// holder republishes call links constantly, and nudging subscribers each time
// would message everyone several times an hour.
func TestRotatedVKLinksAreNotAChange(t *testing.T) {
	store := newStore(t)
	token := issue(t, store, "42")
	notifier := newNotifier()
	links := []string{"aaa", "bbb"}
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith("relay.example", links...), nil
	}), notifier, quiet())

	if _, err := r.RefreshAll(context.Background(), "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	links = []string{"ccc", "ddd"}
	notified, err := r.RefreshAll(context.Background(), "rotation")
	if err != nil {
		t.Fatalf("RefreshAll: %v", err)
	}
	if notified != 0 {
		t.Errorf("notified %d subscribers about a link rotation", notified)
	}

	// The cache still carries the new links, or the client would keep dialling
	// calls that no longer exist.
	cached, _, err := store.BundleCache(token)
	if err != nil {
		t.Fatalf("BundleCache: %v", err)
	}
	if !strings.Contains(string(cached), "ccc") {
		t.Error("the rotated links did not reach the cache")
	}
}

// TestAdoptHashesSaysNothing covers the cutover: a rewritten renderer produces
// an equivalent bundle that hashes differently, and the first refresh would
// otherwise tell every subscriber their configuration changed.
func TestAdoptHashesSaysNothing(t *testing.T) {
	store := newStore(t)
	token := issue(t, store, "42")
	notifier := newNotifier()
	server := "relay.example"
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith(server), nil
	}), notifier, quiet())

	if _, err := r.RefreshAll(context.Background(), "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	server = "renderer-2.example" // stands in for the new implementation

	adopted, err := r.AdoptHashes(context.Background())
	if err != nil {
		t.Fatalf("AdoptHashes: %v", err)
	}
	if adopted != 1 {
		t.Errorf("adopted = %d, want 1", adopted)
	}
	if notifier.told("42") != 0 {
		t.Error("adoption messaged a subscriber")
	}
	// And the adopted hash is the new one, so a later real change is caught.
	notified, err := r.RefreshAll(context.Background(), "after")
	if err != nil {
		t.Fatalf("RefreshAll: %v", err)
	}
	if notified != 0 {
		t.Error("the adopted hash was not the one just rendered")
	}
	server = "relay3.example"
	if notified, err = r.RefreshAll(context.Background(), "real change"); err != nil || notified != 1 {
		t.Errorf("a real change after adoption: notified=%d err=%v", notified, err)
	}
	_ = token
}

// TestOneBadBundleDoesNotStopTheRest: a user whose peer file is gone must not
// cost the other five their refresh.
func TestOneBadBundleDoesNotStopTheRest(t *testing.T) {
	store := newStore(t)
	broken := issue(t, store, "1")
	fine := issue(t, store, "2")
	r := NewRefresher(store, bundleFunc(func(uid string) ([]byte, error) {
		if uid == "1" {
			return nil, errors.New("no peer on file")
		}
		return bundleWith("relay.example"), nil
	}), newNotifier(), quiet())

	if _, err := r.RefreshAll(context.Background(), ""); err != nil {
		t.Fatalf("RefreshAll: %v", err)
	}
	if _, found, _ := store.BundleCache(fine); !found {
		t.Error("the healthy subscriber was not refreshed")
	}
	if _, found, _ := store.BundleCache(broken); found {
		t.Error("a bundle was cached for the user whose build failed")
	}
}

// TestRefreshKeepsATokenIssuedWhileItRan: the rebuild awaits a render per
// subscriber, and writing back the snapshot taken beforehand would delete a
// subscription created in the meantime.
func TestRefreshKeepsATokenIssuedWhileItRan(t *testing.T) {
	store := newStore(t)
	issue(t, store, "1")
	var newToken string
	r := NewRefresher(store, bundleFunc(func(uid string) ([]byte, error) {
		if newToken == "" {
			// Somebody presses the button mid-refresh.
			newToken = issue(t, store, "9")
		}
		return bundleWith("relay.example"), nil
	}), newNotifier(), quiet())

	if _, err := r.RefreshAll(context.Background(), ""); err != nil {
		t.Fatalf("RefreshAll: %v", err)
	}
	subs, err := store.Subscriptions()
	if err != nil {
		t.Fatalf("Subscriptions: %v", err)
	}
	if _, ok := subs[newToken]; !ok {
		t.Error("the subscription issued during the refresh was lost")
	}
	if len(subs) != 2 {
		t.Errorf("subscriptions = %d, want 2", len(subs))
	}
}

func TestADeliveryFailureDoesNotStopTheOthers(t *testing.T) {
	store := newStore(t)
	issue(t, store, "1")
	issue(t, store, "2")
	notifier := newNotifier()
	server := "relay.example"
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith(server), nil
	}), notifier, quiet())
	r.ChangedText = func(string) string { return "changed" }

	if _, err := r.RefreshAll(context.Background(), "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	server = "relay2.example"
	notifier.err = errors.New("bot was blocked by the user")

	notified, err := r.RefreshAll(context.Background(), "")
	if err != nil {
		t.Fatalf("a blocked chat broke the whole refresh: %v", err)
	}
	if notified != 0 {
		t.Errorf("notified = %d despite every delivery failing", notified)
	}
	// The hash is recorded all the same: retrying the nudge forever would
	// message a user who has blocked the bot on every tick.
	subs, _ := store.Subscriptions()
	for token, meta := range subs {
		if meta.LastHash == "" {
			t.Errorf("%s has no hash recorded", token)
		}
	}
}

func TestNotifyWatchConsumesTheMarker(t *testing.T) {
	store := newStore(t)
	issue(t, store, "42")
	notifier := newNotifier()
	server := "relay.example"
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith(server), nil
	}), notifier, quiet())
	r.ChangedText = func(reason string) string { return reason }

	if _, err := r.RefreshAll(context.Background(), "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	server = "relay2.example"
	if err := store.Touch(".notify-subs", "порт DS-Lite сменился"); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.RunNotifyWatch(ctx, ".notify-subs", 5*time.Millisecond) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && notifier.told("42") == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if notifier.told("42") == 0 {
		t.Fatal("the marker was never acted on")
	}
	// The reason the host wrote reaches the subscriber.
	if got := notifier.direct["42"][0]; got != "порт DS-Lite сменился" {
		t.Errorf("message = %q, want the host's reason", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("the watch loop ignored cancellation")
	}
	// Consumed, or the same refresh would run again on every tick.
	if _, found, _ := store.ReadMarker(".notify-subs"); found {
		t.Error("the marker was left in place")
	}
}

func TestRunRefreshStopsOnCancellation(t *testing.T) {
	store := newStore(t)
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith("relay.example"), nil
	}), newNotifier(), quiet())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.RunRefresh(ctx, time.Hour, time.Hour, "") }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want the cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("RunRefresh did not stop")
	}
}

// --- the VK pool ---

type checkFunc func(hashes []string) (map[string]external.HashStatus, error)

func (f checkFunc) Check(_ context.Context, hashes []string) (map[string]external.HashStatus, error) {
	return f(hashes)
}

// seedPool writes a pool the way the bot does.
func seedPool(t *testing.T, store *state.Store, pool state.VKHashes) {
	t.Helper()
	err := store.UpdateVKHashes(func(fresh state.VKHashes) error {
		for hash, entry := range pool {
			fresh[hash] = entry
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed the pool: %v", err)
	}
}

func newChecker(t *testing.T, store *state.Store, notifier Notifier, check checkFunc) *PoolChecker {
	t.Helper()
	p := NewPoolChecker(store, check, notifier, quiet())
	p.DeadText = func(hashes []string) string { return fmt.Sprintf("dead: %v", hashes) }
	p.OwnerText = func(hash string) string { return "your link " + hash + " died" }
	p.LowPoolText = func(live int) string { return fmt.Sprintf("only %d left", live) }
	return p
}

func TestPoolCheckRecordsDeathAndTellsTheSubmitter(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{
		"alive": {Status: "ok", ByName: "someone", By: 7},
		"gone":  {Status: "ok", ByName: "someone", By: 7},
	})
	notifier := newNotifier()
	p := newChecker(t, store, notifier, func([]string) (map[string]external.HashStatus, error) {
		return map[string]external.HashStatus{
			"alive": {Status: "ok"},
			"gone":  {Status: "dead", Detail: "room is gone"},
		}, nil
	})

	summary, err := p.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !slices.Equal(summary.NewlyDead, []string{"gone"}) {
		t.Errorf("newly dead = %v", summary.NewlyDead)
	}
	if summary.Live != 1 {
		t.Errorf("live = %d, want 1", summary.Live)
	}

	pool, _ := store.VKHashes()
	if pool["gone"].Status != "dead" || pool["gone"].Detail != "room is gone" {
		t.Errorf("the verdict was not recorded: %+v", pool["gone"])
	}
	if pool["gone"].Checked == "" {
		t.Error("no check time was recorded")
	}
	// The submitter is the only person who can create a replacement.
	if notifier.told("7") != 1 {
		t.Error("the submitter was not told their link died")
	}
	if len(notifier.admin) == 0 {
		t.Error("the admins were not told")
	}
}

// TestInconclusiveVerdictsDoNotKill is the behaviour that keeps a challenged
// checker from emptying the pool.
func TestInconclusiveVerdictsDoNotKill(t *testing.T) {
	for _, status := range []string{"captcha", "limited", "network", "error"} {
		t.Run(status, func(t *testing.T) {
			store := newStore(t)
			seedPool(t, store, state.VKHashes{"h": {Status: "ok", ByName: "someone", By: 7}})
			notifier := newNotifier()
			p := newChecker(t, store, notifier, func([]string) (map[string]external.HashStatus, error) {
				return map[string]external.HashStatus{"h": {Status: status}}, nil
			})

			summary, err := p.Validate(context.Background())
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if len(summary.NewlyDead) != 0 || len(summary.Pruned) != 0 {
				t.Errorf("a %s verdict was acted on: %+v", status, summary)
			}
			pool, _ := store.VKHashes()
			if _, ok := pool["h"]; !ok {
				t.Errorf("a %s verdict removed the link", status)
			}
			if notifier.told("7") != 0 {
				t.Errorf("a %s verdict messaged the submitter", status)
			}
		})
	}
}

// TestASecondDeathPrunesAManualLink stops flap-spam: a checker that
// intermittently sees a transient "ok" on a truly dead link would otherwise
// announce the same death every round.
func TestASecondDeathPrunesAManualLink(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{
		"manual": {Status: "dead", ByName: "someone", By: 7},
		"held":   {Status: "dead", ByName: "vkcalls-server"},
	})
	notifier := newNotifier()
	p := newChecker(t, store, notifier, func([]string) (map[string]external.HashStatus, error) {
		return map[string]external.HashStatus{
			"manual": {Status: "dead"},
			"held":   {Status: "dead"},
		}, nil
	})

	summary, err := p.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !slices.Equal(summary.Pruned, []string{"manual"}) {
		t.Errorf("pruned = %v, want only the manual link", summary.Pruned)
	}
	pool, _ := store.VKHashes()
	if _, ok := pool["manual"]; ok {
		t.Error("the stale manual link was kept")
	}
	// The holder's links are republished by the holder, so they stay.
	if _, ok := pool["held"]; !ok {
		t.Error("a link the holder owns was pruned")
	}
	// Neither death is new, so nobody is told again.
	if notifier.told("7") != 0 || len(notifier.admin) != 1 {
		t.Errorf("announcements on a repeat death: direct=%d admin=%v",
			notifier.told("7"), notifier.admin)
	}
}

// TestTheHoldersDeathsAreSilent: those die and are recreated as a matter of
// course, and announcing each would train everyone to ignore the channel.
func TestTheHoldersDeathsAreSilent(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{
		"held":  {Status: "ok", ByName: "vkcalls-server"},
		"held2": {Status: "ok", ByName: "vkcalls-server"},
		"held3": {Status: "ok", ByName: "vkcalls-server"},
	})
	notifier := newNotifier()
	p := newChecker(t, store, notifier, func([]string) (map[string]external.HashStatus, error) {
		return map[string]external.HashStatus{"held": {Status: "dead"}}, nil
	})

	summary, err := p.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !slices.Equal(summary.NewlyDead, []string{"held"}) {
		t.Errorf("newly dead = %v", summary.NewlyDead)
	}
	if len(notifier.admin) != 0 {
		t.Errorf("the holder's routine death was announced: %v", notifier.admin)
	}
}

// TestAnEmptyingPoolWakesTheAdmins: a dead link is routine, a pool with nothing
// left in it stops the whole path for everyone.
func TestAnEmptyingPoolWakesTheAdmins(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{
		"a": {Status: "ok", ByName: "vkcalls-server"},
		"b": {Status: "ok", ByName: "vkcalls-server"},
	})
	notifier := newNotifier()
	p := newChecker(t, store, notifier, func([]string) (map[string]external.HashStatus, error) {
		return map[string]external.HashStatus{
			"a": {Status: "dead"},
			"b": {Status: "dead"},
		}, nil
	})

	summary, err := p.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if summary.Live != 0 {
		t.Errorf("live = %d", summary.Live)
	}
	if len(notifier.admin) != 1 || !strings.Contains(notifier.admin[0], "only 0 left") {
		t.Errorf("admin messages = %v, want the low-pool alarm", notifier.admin)
	}
}

// TestAFailedCheckChangesNothing: the helper is a network tool talking to a
// service that rate-limits, and treating silence as death would wipe the pool.
func TestAFailedCheckChangesNothing(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{"h": {Status: "ok", ByName: "someone"}})
	notifier := newNotifier()
	p := newChecker(t, store, notifier, func([]string) (map[string]external.HashStatus, error) {
		return nil, nil // ran, concluded nothing
	})

	if _, err := p.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pool, _ := store.VKHashes()
	if pool["h"].Status != "ok" {
		t.Errorf("status = %q, want it untouched", pool["h"].Status)
	}
	if len(notifier.admin) != 0 {
		t.Errorf("a check that concluded nothing raised the alarm: %v", notifier.admin)
	}
}

func TestAnEmptyPoolIsNotChecked(t *testing.T) {
	store := newStore(t)
	called := false
	p := newChecker(t, store, newNotifier(), func([]string) (map[string]external.HashStatus, error) {
		called = true
		return nil, nil
	})
	if _, err := p.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if called {
		t.Error("the helper was run with nothing to check")
	}
}

// TestPoolCheckKeepsALinkAddedWhileItRan: a check takes about a minute per
// link, and a link submitted meanwhile must not be dropped by the write-back.
func TestPoolCheckKeepsALinkAddedWhileItRan(t *testing.T) {
	store := newStore(t)
	seedPool(t, store, state.VKHashes{"old": {Status: "ok", ByName: "someone"}})
	p := newChecker(t, store, newNotifier(), func([]string) (map[string]external.HashStatus, error) {
		seedPool(t, store, state.VKHashes{"fresh": {Status: "ok", ByName: "someone"}})
		return map[string]external.HashStatus{"old": {Status: "dead"}}, nil
	})

	if _, err := p.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pool, _ := store.VKHashes()
	if _, ok := pool["fresh"]; !ok {
		t.Error("the link submitted during the check was lost")
	}
}

func TestRunValidateStopsOnCancellation(t *testing.T) {
	store := newStore(t)
	p := newChecker(t, store, newNotifier(), func([]string) (map[string]external.HashStatus, error) {
		return nil, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.RunValidate(ctx, time.Hour, time.Hour) }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("RunValidate did not stop")
	}
}

// recordingHandler captures log records so a test can assert on them.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) find(message string) (slog.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, record := range h.records {
		if record.Message == message {
			return record, true
		}
	}
	return slog.Record{}, false
}

// TestAQuietRefreshIsStillReported is the "silence is not success" fix.
//
// With nothing to announce, RefreshAll used to return before logging anything,
// so a log with no refresh line meant either "nothing changed" or "the loop
// never ran" -- indistinguishable. That is the single most important signal
// after a cutover, where zero changes is exactly the expected outcome, and
// confirming it meant reading file timestamps instead.
func TestAQuietRefreshIsStillReported(t *testing.T) {
	store := newStore(t)
	issue(t, store, "42")
	handler := &recordingHandler{}
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) {
		return bundleWith("relay.example"), nil
	}), newNotifier(), slog.New(handler))

	// Twice: the first seeds the hash, the second is the genuinely quiet round.
	for range 2 {
		if _, err := r.RefreshAll(context.Background(), "сверка"); err != nil {
			t.Fatalf("RefreshAll: %v", err)
		}
	}

	record, found := handler.find("rebuilt subscriptions")
	if !found {
		t.Fatal("a refresh that changed nothing logged nothing, so it cannot be told from a loop that never ran")
	}

	attrs := map[string]string{}
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	if attrs["changed"] != "0" {
		t.Errorf("changed = %q, want 0", attrs["changed"])
	}
	if attrs["rebuilt"] != "1" {
		t.Errorf("rebuilt = %q, want the one subscription", attrs["rebuilt"])
	}
	// The reason travels too, so a host-triggered refresh is distinguishable
	// from the timer's in a log.
	if attrs["reason"] != "сверка" {
		t.Errorf("reason = %q", attrs["reason"])
	}
}

// A restored or moved server announces the new subscription link once, to
// every subscriber, with their own token in it; the first start and every
// unchanged one say nothing.
func TestAnnounceMoveSendsTheNewLinkOnce(t *testing.T) {
	store := newStore(t)
	alice := issue(t, store, "1")
	issue(t, store, "2")
	notifier := newNotifier()
	r := NewRefresher(store, bundleFunc(func(string) ([]byte, error) { return nil, nil }), notifier, quiet())
	links := func(base state.SubscriptionBase) Links {
		return func(token string) (string, string) {
			return "", "http://" + base.HostDirect + "/sub/" + token
		}
	}
	text := func(cf, direct string) string { return direct }
	ctx := context.Background()

	old := state.SubscriptionBase{HostDirect: "203.0.113.7:10873"}
	if n, err := r.AnnounceMove(ctx, old, links(old), text); err != nil || n != 0 {
		t.Fatalf("first start: notified %d, %v", n, err)
	}
	if n, _ := r.AnnounceMove(ctx, old, links(old), text); n != 0 {
		t.Fatalf("an unchanged start notified %d", n)
	}

	moved := state.SubscriptionBase{HostDirect: "198.51.100.9:10873"}
	n, err := r.AnnounceMove(ctx, moved, links(moved), text)
	if err != nil || n != 2 {
		t.Fatalf("after the move: notified %d, %v", n, err)
	}
	if got := notifier.direct["1"]; len(got) != 1 || got[0] != "http://198.51.100.9:10873/sub/"+alice {
		t.Fatalf("subscriber 1 was told %q", got)
	}
	if n, _ := r.AnnounceMove(ctx, moved, links(moved), text); n != 0 {
		t.Fatalf("a restart after the move notified %d again", n)
	}
}
