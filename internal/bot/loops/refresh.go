// Package loops runs the bot's background work: keeping every subscription
// cache current, and keeping the VK call pool honest.
//
// Both exist because the configuration a client holds can go stale without the
// client or the bot doing anything. A VK call link dies, the DS-Lite port moves,
// a key is rotated on the server. The refresher notices generically, by
// rebuilding each bundle and comparing it to what the subscriber last saw,
// rather than by wiring a notification into every one of those triggers.
package loops

import (
	"context"
	"log/slog"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Builder renders a subscriber's bundle.
//
// It must not provision: this runs every minute for every subscriber, and
// minting keys or registering peers on a timer would grow the config for
// someone who has not asked for anything.
type Builder interface {
	Bundle(ctx context.Context, uid string) ([]byte, error)
}

// Notifier delivers messages. Separate from the Telegram client so the
// refresher can be exercised, and so a delivery failure to one subscriber does
// not stop the rebuild for the rest.
type Notifier interface {
	Notify(ctx context.Context, uid, text string) error
	NotifyAdmins(ctx context.Context, text string) error
}

// Refresher rebuilds subscription caches and tells subscribers whose
// configuration actually changed.
type Refresher struct {
	store    *state.Store
	builder  Builder
	notifier Notifier
	// ChangedText renders the message sent to a subscriber whose bundle
	// changed, given the reason. Configurable because every user-facing string
	// belongs in the config, not in this package.
	ChangedText func(reason string) string
	log         *slog.Logger
}

// NewRefresher builds a refresher.
func NewRefresher(store *state.Store, builder Builder, notifier Notifier, log *slog.Logger) *Refresher {
	if log == nil {
		log = slog.Default()
	}
	return &Refresher{store: store, builder: builder, notifier: notifier, log: log}
}

// RefreshAll rebuilds every cache and returns how many subscribers were told.
//
// reason is passed through to the message, so a subscriber reading "the VK call
// was replaced" knows why their client reconnected.
func (r *Refresher) RefreshAll(ctx context.Context, reason string) (int, error) {
	changed, rebuilt, err := r.rebuild(ctx, true)
	if err != nil {
		return 0, err
	}
	// Logged on every round, including the quiet one.
	//
	// Silence is not success: with nothing to announce this used to return
	// before saying anything, so a log with no refresh line meant either
	// "nothing changed" or "the loop never ran" and there was no way to tell.
	// That is the single most important signal after a cutover, where the
	// expected outcome is precisely zero changes.
	r.log.Info("rebuilt subscriptions",
		"rebuilt", rebuilt, "changed", len(changed), "reason", reason)

	if len(changed) == 0 || r.notifier == nil {
		return 0, nil
	}

	text := "Конфигурация на сервере изменилась — подписка обновится сама."
	if r.ChangedText != nil {
		text = r.ChangedText(reason)
	}
	notified := 0
	for _, uid := range changed {
		if err := r.notifier.Notify(ctx, uid, text); err != nil {
			// One blocked chat must not stop the rest: the cache is already
			// written, so the client picks the change up on its next poll
			// whether or not the nudge arrived.
			r.log.Warn("could not nudge a subscriber", "uid", uid, "error", err)
			continue
		}
		notified++
	}
	r.log.Info("refreshed subscriptions", "changed", len(changed), "notified", notified, "reason", reason)
	return notified, nil
}

// AdoptHashes rebuilds every cache and records the resulting hash without
// telling anyone.
//
// This is for a cutover. A rewritten renderer produces a structurally equal
// bundle that does not hash the same as the previous implementation's, and the
// first refresh afterwards would tell every subscriber their configuration
// changed when nothing about their access did. Run once, then start the loop.
func (r *Refresher) AdoptHashes(ctx context.Context) (int, error) {
	adopted, _, err := r.rebuild(ctx, false)
	if err != nil {
		return 0, err
	}
	r.log.Info("adopted the current subscription hashes", "tokens", len(adopted))
	return len(adopted), nil
}

// rebuild writes every cache and records the hashes, returning the uids whose
// bundle differs from what they last saw and how many were rebuilt at all.
// When notice is false the comparison is skipped and every token is adopted.
func (r *Refresher) rebuild(ctx context.Context, notice bool) ([]string, int, error) {
	subscriptions, err := r.store.Subscriptions()
	if err != nil {
		return nil, 0, err
	}

	var changed []string
	hashes := map[string]string{}
	for token, meta := range subscriptions {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if meta.UID == "" {
			r.log.Warn("a subscription has no owner and was left alone", "token", token)
			continue
		}

		bundle, err := r.builder.Bundle(ctx, meta.UID)
		if err != nil {
			// Skipped rather than fatal: one user whose bundle cannot be built
			// -- an endpoint removed, a peer file gone -- must not stop the
			// other five from being refreshed.
			r.log.Error("could not rebuild a bundle", "uid", meta.UID, "error", err)
			continue
		}
		hash, err := clientcfg.StructuralHash(bundle)
		if err != nil {
			r.log.Error("could not hash a bundle", "uid", meta.UID, "error", err)
			continue
		}
		// The cache holds the whole bundle including the parts the hash
		// ignores, so a client still receives the rotated VK links.
		if err := r.store.SetBundleCache(token, bundle); err != nil {
			return nil, 0, err
		}

		// An unseen token is seeded silently. Otherwise every subscriber would
		// be told their configuration changed the first time the bot started.
		if notice && meta.LastHash != "" && meta.LastHash != hash {
			changed = append(changed, meta.UID)
		}
		hashes[token] = hash
	}

	// Merged under the store's lock rather than written from the snapshot taken
	// before all that building: only last_hash is ours to set, and only for
	// tokens that still exist. A subscription issued while this ran must
	// survive, and one deleted while this ran must not come back.
	err = r.store.UpdateSubscriptions(func(fresh state.Subscriptions) error {
		for token, hash := range hashes {
			meta, ok := fresh[token]
			if !ok {
				continue
			}
			meta.LastHash = hash
			fresh[token] = meta
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	if !notice {
		adopted := make([]string, 0, len(hashes))
		for token := range hashes {
			adopted = append(adopted, token)
		}
		return adopted, len(hashes), nil
	}
	return changed, len(hashes), nil
}

// RunRefresh refreshes every interval until the context is cancelled.
//
// The period covers any change source generically. The settle delay is there
// because at startup the pool has not been validated and the endpoints may not
// have been applied yet, and a bundle built from that half-known state would
// hash differently and nudge everyone for nothing.
func (r *Refresher) RunRefresh(ctx context.Context, interval, settle time.Duration, reason string) error {
	if err := sleep(ctx, settle); err != nil {
		return err
	}
	for {
		if _, err := r.RefreshAll(ctx, reason); err != nil && ctx.Err() == nil {
			r.log.Error("the refresh loop failed this round", "error", err)
		}
		if err := sleep(ctx, interval); err != nil {
			return err
		}
	}
}

// RunNotifyWatch refreshes as soon as something on the host asks it to.
//
// Host-side units -- the port sync, the call holder -- know a change happened
// before the bot could notice it, and touch the marker with a short reason.
// Polling a file is how they reach a process with no socket of its own.
func (r *Refresher) RunNotifyWatch(ctx context.Context, marker string, interval time.Duration) error {
	for {
		if err := sleep(ctx, interval); err != nil {
			return err
		}
		reason, found, err := r.store.ReadMarker(marker)
		if err != nil {
			r.log.Warn("could not read the notify marker", "error", err)
			continue
		}
		if !found {
			continue
		}
		// Removed before the refresh, not after: a rebuild that takes longer
		// than the interval would otherwise be started again on the next tick.
		if err := r.store.Remove(marker); err != nil {
			r.log.Warn("could not clear the notify marker", "error", err)
		}
		if _, err := r.RefreshAll(ctx, reason); err != nil && ctx.Err() == nil {
			r.log.Error("a host-triggered refresh failed", "reason", reason, "error", err)
		}
	}
}

// sleep waits, or returns the cancellation.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
