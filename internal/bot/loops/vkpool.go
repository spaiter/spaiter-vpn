package loops

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Checker validates VK call links.
type Checker interface {
	Check(ctx context.Context, hashes []string) (map[string]external.HashStatus, error)
}

// PoolChecker keeps the VK call pool honest: a link that has stopped working is
// still in every client's bundle until something notices.
type PoolChecker struct {
	store    *state.Store
	checker  Checker
	notifier Notifier
	log      *slog.Logger

	// HolderName is the submitter recorded for links the call-holder service
	// publishes. Those die and are republished as a matter of course, so they
	// are neither announced nor pruned -- the holder owns them.
	HolderName string
	// LowWaterMark is how few live links count as an emergency worth waking an
	// admin for.
	LowWaterMark int
	// DeadText and LowPoolText render the two messages. Both are user-facing,
	// so they come from the config rather than from this package.
	DeadText    func(hashes []string) string
	OwnerText   func(hash string) string
	LowPoolText func(live int) string
}

// NewPoolChecker builds a pool checker.
func NewPoolChecker(store *state.Store, checker Checker, notifier Notifier, log *slog.Logger) *PoolChecker {
	if log == nil {
		log = slog.Default()
	}
	return &PoolChecker{
		store:        store,
		checker:      checker,
		notifier:     notifier,
		log:          log,
		HolderName:   "vkcalls-server",
		LowWaterMark: 2,
	}
}

// Summary is what one validation round concluded.
type Summary struct {
	// Checked is how many links the helper reached a verdict on.
	Checked int
	// Live is how many links remain usable afterwards.
	Live int
	// NewlyDead are the links that died this round.
	NewlyDead []string
	// Pruned are the links dropped from the pool entirely.
	Pruned []string
}

// Validate checks every pooled link and records what it found.
//
// A verdict the helper could not reach is left alone rather than recorded as a
// failure: a captcha or a rate limit says nothing about the link, and writing
// it off would empty the pool because the checker happened to be challenged.
func (p *PoolChecker) Validate(ctx context.Context) (Summary, error) {
	pool, err := p.store.VKHashes()
	if err != nil {
		return Summary{}, err
	}
	if len(pool) == 0 {
		return Summary{}, nil
	}

	hashes := make([]string, 0, len(pool))
	for hash := range pool {
		hashes = append(hashes, hash)
	}
	// Sorted so the helper joins them in a stable order and a log from two
	// rounds can be compared.
	slices.Sort(hashes)

	verdicts, err := p.checker.Check(ctx, hashes)
	if err != nil {
		return Summary{}, err
	}
	if len(verdicts) == 0 {
		// The helper ran and concluded nothing. Not an error -- it is a network
		// tool talking to a service that rate-limits -- but nothing to record.
		p.log.Warn("the VK pool check produced no verdicts", "hashes", len(hashes))
		return Summary{}, nil
	}

	summary := Summary{Checked: len(verdicts)}
	now := state.Now()
	err = p.store.UpdateVKHashes(func(fresh state.VKHashes) error {
		for hash, verdict := range verdicts {
			entry, ok := fresh[hash]
			if !ok {
				// Removed while the check ran, which takes a minute per link.
				continue
			}
			wasDead := entry.Status == "dead"
			entry.Status = verdict.Status
			entry.Checked = now
			entry.Detail = verdict.Detail
			fresh[hash] = entry

			if !verdict.Dead() {
				continue
			}
			if !wasDead {
				summary.NewlyDead = append(summary.NewlyDead, hash)
				continue
			}
			// Dead for a second consecutive check, and nobody is going to
			// refresh it: a link the holder owns is republished by the holder,
			// a link a human submitted is theirs to replace. Pruning the
			// latter also stops flap-spam, since a checker that intermittently
			// sees a transient "ok" on a truly dead link would otherwise
			// announce the same death every round.
			if entry.ByName != p.HolderName {
				summary.Pruned = append(summary.Pruned, hash)
				delete(fresh, hash)
			}
		}
		for _, entry := range fresh {
			if entry.Status != "dead" {
				summary.Live++
			}
		}
		return nil
	})
	if err != nil {
		return Summary{}, err
	}
	slices.Sort(summary.NewlyDead)
	slices.Sort(summary.Pruned)

	p.announce(ctx, pool, summary)
	p.log.Info("validated the VK pool",
		"checked", summary.Checked, "live", summary.Live,
		"newly_dead", summary.NewlyDead, "pruned", summary.Pruned)
	return summary, nil
}

// announce tells the people who can do something about what was found.
//
// Deliberately quiet about the holder's links: those die and are recreated
// routinely, and announcing each one would train everyone to ignore the
// channel. Subscribers are not told at all -- the pool is redundant and their
// client refreshes on its own, so a rotated link is not a change in their
// access.
func (p *PoolChecker) announce(ctx context.Context, before state.VKHashes, summary Summary) {
	if p.notifier == nil {
		return
	}

	var manual []string
	for _, hash := range summary.NewlyDead {
		if before[hash].ByName != p.HolderName {
			manual = append(manual, hash)
		}
	}

	if len(manual) > 0 {
		if p.DeadText != nil {
			if err := p.notifier.NotifyAdmins(ctx, p.DeadText(manual)); err != nil {
				p.log.Warn("could not tell the admins about dead links", "error", err)
			}
		}
		// And the person who submitted each one, who is the only one who can
		// create a replacement.
		if p.OwnerText != nil {
			admins, err := p.store.Admins()
			if err != nil {
				p.log.Warn("could not read the admin list", "error", err)
				admins = nil
			}
			for _, hash := range manual {
				owner := before[hash].By
				if owner == 0 || slices.Contains(admins, owner) {
					continue // already told as an admin
				}
				uid := strconv.FormatInt(owner, 10)
				if err := p.notifier.Notify(ctx, uid, p.OwnerText(hash)); err != nil {
					p.log.Warn("could not tell a submitter their link died",
						"uid", uid, "error", err)
				}
			}
		}
	}

	// The real emergency is not a dead link but an empty pool: with nothing to
	// hand out, the whole path stops working for everyone.
	if summary.Live < p.LowWaterMark && p.LowPoolText != nil {
		if err := p.notifier.NotifyAdmins(ctx, p.LowPoolText(summary.Live)); err != nil {
			p.log.Warn("could not raise the low-pool alarm", "error", err)
		}
	}
}

// RunValidate validates the pool every interval until the context is cancelled.
//
// The settle delay lets the holder service publish its links after a restart;
// checking before that would find an empty pool and raise the alarm about it.
func (p *PoolChecker) RunValidate(ctx context.Context, interval, settle time.Duration) error {
	if err := sleep(ctx, settle); err != nil {
		return err
	}
	for {
		if _, err := p.Validate(ctx); err != nil && ctx.Err() == nil {
			p.log.Error("the VK pool check failed this round", "error", err)
		}
		if err := sleep(ctx, interval); err != nil {
			return err
		}
	}
}
