package loops

import (
	"context"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Links renders a subscriber's two subscription URLs for a token.
type Links func(token string) (cf, direct string)

// AnnounceMove tells every subscriber their subscription link changed, when the
// links this bot hands out no longer point where the recorded ones did.
//
// The refresh loop cannot cover this. It tells a subscriber that their
// configuration changed and that the client will pick it up, which is true only
// while the subscription URL still works; after the server moves to another
// address, or a backup is restored onto a new server, the client keeps polling
// the old one and nothing reaches it. The new link has to be delivered by hand,
// once, and this is that delivery.
//
// The first run records the base without telling anyone: there is no earlier
// link to have changed. A subscriber who cannot be reached is skipped and
// logged; the base is recorded regardless, so a restart does not message the
// others twice.
func (r *Refresher) AnnounceMove(ctx context.Context, current state.SubscriptionBase, links Links, text func(cf, direct string) string) (int, error) {
	previous, found, err := r.store.SubscriptionBase()
	if err != nil {
		return 0, err
	}
	if found && previous == current {
		return 0, nil
	}
	if !found || r.notifier == nil || (current.HostCF == "" && current.HostDirect == "") {
		return 0, r.store.SetSubscriptionBase(current)
	}

	subscriptions, err := r.store.Subscriptions()
	if err != nil {
		return 0, err
	}
	notified := 0
	for token, meta := range subscriptions {
		if err := ctx.Err(); err != nil {
			return notified, err
		}
		if meta.UID == "" {
			continue
		}
		cf, direct := links(token)
		if err := r.notifier.Notify(ctx, meta.UID, text(cf, direct)); err != nil {
			r.log.Warn("could not send the moved subscription link", "uid", meta.UID, "error", err)
			continue
		}
		notified++
	}
	r.log.Info("subscription links moved",
		"from_cf", previous.HostCF, "from_direct", previous.HostDirect,
		"to_cf", current.HostCF, "to_direct", current.HostDirect,
		"subscribers", len(subscriptions), "notified", notified)
	return notified, r.store.SetSubscriptionBase(current)
}
