package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	tgbot "github.com/go-telegram/bot"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/loops"
	"github.com/spaiter/spaiter-vpn/internal/bot/monitor"
	"github.com/spaiter/spaiter-vpn/internal/bot/provision"
	"github.com/spaiter/spaiter-vpn/internal/bot/reload"
	"github.com/spaiter/spaiter-vpn/internal/bot/service"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/bot/subserver"
	"github.com/spaiter/spaiter-vpn/internal/bot/telegram"
	"github.com/spaiter/spaiter-vpn/internal/bot/ui"
	"github.com/spaiter/spaiter-vpn/internal/bot/webapp"
	"github.com/spaiter/spaiter-vpn/internal/control"
	"github.com/spaiter/spaiter-vpn/internal/guide"
	"github.com/spaiter/spaiter-vpn/internal/manage"
	"github.com/spaiter/spaiter-vpn/internal/web"
)

// runBot is the provisioning bot: Telegram front end, the subscription server
// and the background loops.
//
// It lives in this binary rather than beside it so that the generators and the
// core's option types cannot drift apart -- which they did, twice, when the bot
// was a separate Python program. Everything host-specific comes from the config
// file; the Telegram token comes from the environment, because secrets in this
// repository live apart from configuration.
func runBot(ctx context.Context, out io.Writer, args []string) error {
	if len(args) > 0 && args[0] == "claim-code" {
		return runBotClaimCode(out, args[1:])
	}
	if len(args) > 0 && args[0] == "guide" {
		return runBotGuide(ctx, out, args[1:])
	}
	if len(args) > 0 && args[0] == "notify" {
		return runBotNotify(ctx, out, args[1:])
	}
	fs := newFlagSet("bot", out)
	configPath := fs.String("config", "", "path to bot.json (defaults are this deployment's)")
	checkOnly := fs.Bool("check-config", false, "load the config, report it and exit")
	noTelegram := fs.Bool("no-telegram", false,
		"run the subscription server and loops without answering Telegram")
	adoptHashes := fs.Bool("adopt-hashes", false,
		"record every subscription's current hash without notifying anyone, then exit")
	subPort := fs.Uint("sub-port", 0, "override the subscription port (for running beside another bot)")
	compare := fs.Bool("compare", false,
		"rebuild every subscription and diff it against the cache on disk, writing nothing")
	verbose := fs.Bool("v", false, "log at debug level")
	pprofAddr := fs.String("pprof", "", "serve runtime profiles (net/http/pprof, incl. goroutineleak) on this loopback address, e.g. 127.0.0.1:6060")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := botcfg.Load(*configPath)
	if err != nil {
		return err
	}
	if *subPort != 0 {
		cfg.Subscription.Port = uint16(*subPort)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *checkOnly {
		return describeBotConfig(out, cfg)
	}

	parts, err := buildBot(cfg, log)
	if err != nil {
		return err
	}

	if *adoptHashes {
		// The cutover step. A rewritten renderer produces an equivalent bundle
		// that does not hash the same as the previous implementation's, and the
		// first refresh afterwards would tell every subscriber their
		// configuration had changed when nothing about their access did.
		adopted, err := parts.refresher.AdoptHashes(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "adopted %d subscription hash(es) without notifying anyone\n", adopted)
		return nil
	}

	if *compare {
		return compareSubscriptions(ctx, out, parts)
	}

	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" && !*noTelegram {
		return fmt.Errorf("%w: TELEGRAM_TOKEN is not set; "+
			"pass -no-telegram to run only the subscription server and the loops", ErrUsage)
	}

	if err := servePprof(ctx, *pprofAddr, log); err != nil {
		return fmt.Errorf("pprof: %w", err)
	}
	return runBotServices(ctx, out, cfg, parts, token, *noTelegram, log)
}

// botParts is everything assembled, kept together so the wiring is one function
// and the running is another.
type botParts struct {
	store     *state.Store
	api       *manage.Client
	reloader  *reload.Reloader
	svc       *service.Service
	refresher *loops.Refresher
	pool      *loops.PoolChecker
	checker   *external.HashChecker
	notifier  *deferredNotifier
	access    *ui.Access
	face      *ui.UI
	monitor   *monitor.Monitor
}

// buildBot wires the bot up without starting anything, so -check-config and
// -adopt-hashes pay for no listeners.
func buildBot(cfg botcfg.Config, log *slog.Logger) (*botParts, error) {
	store, err := state.New(cfg.Paths.DataDir)
	if err != nil {
		return nil, err
	}

	// The clash API's address and secret are read out of the core's own config,
	// so they cannot disagree with what it is listening on.
	var api *manage.Client
	if cfg.Core.ManagementPath != "" {
		api, err = manage.NewFromCredentialsFile(cfg.Core.ManagementPath)
	} else {
		api, err = manage.NewFromCoreConfig(cfg.Core.ConfigPath)
	}
	if err != nil {
		return nil, fmt.Errorf("bot: reach the core: %w", err)
	}

	reloader := reload.New(applyAdapter{api}, store, reloadMarkerName, log)
	registrar := external.NewWARPRegistrar(cfg.Paths.WARPBinary,
		func(cacheDB string) any { return clientcfg.WARPRegistrationConfig(cfg, cacheDB) }, log)
	checker := external.NewHashChecker(cfg.Paths.CheckHashBinary, log)

	prov := provision.New(api, store, reloader, log)
	svc := service.New(cfg, api, prov, store, reloader, registrar, log)

	// The notifier needs a Telegram client that does not exist until the
	// handlers are registered, and the loops need a notifier now. The deferred
	// one closes that circle without a nil dereference at startup.
	notifier := &deferredNotifier{log: log}

	// readOnlyBundles is what the loop is given, so "never provision" is a type
	// rather than a habit: there is no argument it could pass to create
	// something for a user who pressed nothing.
	refresher := loops.NewRefresher(store, readOnlyBundles{svc}, notifier, log)
	refresher.ChangedText = func(reason string) string {
		if reason == "" {
			reason = cfg.UI.Buttons["change_default_reason"]
		}
		return fmt.Sprintf(cfg.UI.Messages["subscription_changed"], reason)
	}

	pool := loops.NewPoolChecker(store, checker, notifier, log)
	pool.DeadText = func(hashes []string) string {
		return fmt.Sprintf(cfg.UI.Messages["vk_pool_dead"], joinHashes(hashes))
	}
	pool.OwnerText = func(string) string { return cfg.UI.Messages["vk_link_died"] }
	pool.LowPoolText = func(live int) string {
		return fmt.Sprintf(cfg.UI.Messages["vk_pool_low"], live)
	}

	access := ui.NewAccess(store, log)
	face := ui.New(cfg, svc, access, store, log)
	face.SetValidator(checker)
	face.SetPoolChecker(pool)
	face.SetRefresher(refresher)
	if cfg.Paths.ControlSocket != "" {
		face.SetControl(control.Client{Socket: cfg.Paths.ControlSocket})
	}
	if cfg.Web.URL != "" && cfg.Web.KeyPath != "" {
		face.SetWebLogin(func() (string, error) {
			key, err := web.LoadKey(cfg.Web.KeyPath)
			if err != nil {
				return "", err
			}
			token, err := web.LoginToken(key, time.Now().Add(10*time.Minute))
			if err != nil {
				return "", err
			}
			return strings.TrimRight(cfg.Web.URL, "/") + "/login?token=" + token, nil
		})
	}

	mon := buildMonitor(cfg, api, store, notifier, log)
	if mon != nil {
		face.SetHealth(mon.Status)
	}

	return &botParts{
		store: store, api: api, reloader: reloader, svc: svc,
		refresher: refresher, pool: pool, checker: checker,
		notifier: notifier, access: access, face: face, monitor: mon,
	}, nil
}

// readOnlyBundles narrows the service to the one call a background loop may
// make.
type readOnlyBundles struct{ svc *service.Service }

func (r readOnlyBundles) Bundle(ctx context.Context, uid string) ([]byte, error) {
	return r.svc.Bundle(ctx, uid, false)
}

// reloadMarkerName is the file the bot touches to ask for a core reload.
// Something privileged watches it; the bot has no Docker socket by design.
const reloadMarkerName = ".reload-singbox"

// runBotServices starts the subscription server, the loops and -- unless asked
// not to -- the Telegram client, and runs until the context is cancelled.
//
// A failure in any of them stops the rest. The subscription server going down
// is not survivable: clients would keep polling a dead port and silently fall
// back to whatever they last cached.
func runBotServices(ctx context.Context, out io.Writer, cfg botcfg.Config,
	parts *botParts, token string, noTelegram bool, log *slog.Logger,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var client *tgbot.Bot
	if !noTelegram {
		var err error
		options := parts.face.Options()
		if cfg.TelegramAPIURL != "" {
			options = append(options, tgbot.WithServerURL(cfg.TelegramAPIURL))
		}
		client, err = tgbot.New(token, options...)
		if err != nil {
			return fmt.Errorf("bot: build the Telegram client: %w", err)
		}
		parts.face.Attach(client)
		parts.notifier.set(telegram.NewNotifier(client, parts.store, log))
		// The command menu and description are a courtesy, published in the
		// background so a slow or old API server does not hold up startup.
		go parts.face.Announce(ctx)
	}

	type result struct {
		what string
		err  error
	}
	// Room for every loop below, so none blocks on its result after the
	// first one has been taken.
	done := make(chan result, 8)
	var wg sync.WaitGroup

	start := func(what string, run func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done <- result{what, run()}
		}()
	}

	// The Mini App rides on the subscription port. It needs the bot token to
	// check Telegram's signature, so without Telegram there is nothing it
	// could authenticate and it is not mounted.
	subs := subserver.New(parts.store, log)
	if token != "" && webapp.URL(cfg) != "" {
		app := webapp.New(cfg, parts.svc, parts.access, parts.store, token, log)
		app.OnAccessRequest = parts.face.NotifyAccessRequest
		app.Tell = parts.face.Tell
		parts.face.SetWebAppLogin(func(uid int64) (string, error) {
			return app.LoginLink(uid, time.Now())
		})
		subs.Mount(webapp.Prefix, app.Handler())
		log.Info("mini app mounted", "url", webapp.URL(cfg))
	}
	start("subscription server", func() error {
		return subs.Run(ctx, fmt.Sprintf(":%d", cfg.Subscription.Port))
	})
	start("subscription refresh", func() error {
		return parts.refresher.RunRefresh(ctx,
			cfg.Intervals.SubRefresh.Build(), subRefreshSettle, "")
	})
	start("notify watch", func() error {
		return parts.refresher.RunNotifyWatch(ctx,
			notifyMarkerName, cfg.Intervals.NotifyPoll.Build())
	})
	start("VK pool check", func() error {
		return parts.pool.RunValidate(ctx, cfg.Intervals.HashCheck.Build(), poolCheckSettle)
	})
	if parts.monitor != nil {
		start("monitor", func() error { return parts.monitor.Run(ctx) })
	}

	if client != nil {
		// Start blocks until the context is cancelled and reports nothing, so
		// it is not one of the results above.
		go client.Start(ctx)
		// Once, at start: a server that moved, or a backup restored onto a new
		// one, leaves every subscriber polling a link to the old address.
		go func() {
			base := state.SubscriptionBase{HostCF: cfg.Subscription.HostCF, HostDirect: cfg.Subscription.HostDirect}
			text := func(cf, direct string) string {
				if cf == "" {
					cf = direct
				}
				if direct == "" {
					direct = cf
				}
				return fmt.Sprintf(cfg.UI.Messages["subscription_moved"], cf, direct)
			}
			if _, err := parts.refresher.AnnounceMove(ctx, base, parts.face.SubscriptionURLs, text); err != nil {
				log.Warn("could not announce the moved subscription links", "error", err)
			}
		}()
		fmt.Fprintf(out, "bot: answering Telegram, serving /sub on :%d\n", cfg.Subscription.Port)
	} else {
		fmt.Fprintf(out, "bot: Telegram disabled, serving /sub on :%d\n", cfg.Subscription.Port)
	}

	first := <-done
	cancel()
	wg.Wait()

	if first.err != nil && !errors.Is(first.err, context.Canceled) {
		return fmt.Errorf("bot: %s stopped: %w", first.what, first.err)
	}
	return nil
}

// Settle delays. Both exist because a loop that runs at startup reads state
// that is not ready yet: the pool has not been validated and the endpoints may
// not have been applied, and a bundle built from that would hash differently
// and nudge every subscriber for nothing.
var (
	subRefreshSettle = 20 * time.Second
	poolCheckSettle  = 30 * time.Second
)

// notifyMarkerName is touched by host units that know about a change before the
// bot could notice it.
const notifyMarkerName = ".notify-subs"

// applyAdapter translates the management client's apply result into the shape
// the reload package defines.
//
// The translation exists so neither package depends on the other: reload does
// not know how to speak to a core, and the client does not know about batching.
type applyAdapter struct{ api *manage.Client }

func (a applyAdapter) Apply(ctx context.Context) (*reload.ApplyResult, error) {
	result, err := a.api.Apply(ctx)
	if err != nil {
		return nil, err
	}
	return &reload.ApplyResult{
		Inbounds:  outcome(result.Inbounds),
		Endpoints: outcome(result.Endpoints),
	}, nil
}

func (a applyAdapter) Version(ctx context.Context) error { return a.api.Version(ctx) }

func outcome(o manage.ApplyOutcome) reload.Outcome {
	return reload.Outcome{
		Reloaded:  o.Reloaded,
		Recreated: o.Recreated,
		Added:     o.Added,
		Removed:   o.Removed,
	}
}

// deferredNotifier lets the loops hold a notifier before the Telegram client
// exists, and silently drops messages while it does not.
//
// Dropping is right: with -no-telegram there is nowhere to send, and a loop
// that failed on every tick for want of a chat would bury its real output.
type deferredNotifier struct {
	mu    sync.RWMutex
	inner loops.Notifier
	log   *slog.Logger
}

func (d *deferredNotifier) set(inner loops.Notifier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inner = inner
}

func (d *deferredNotifier) get() loops.Notifier {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.inner
}

func (d *deferredNotifier) Notify(ctx context.Context, uid, text string) error {
	inner := d.get()
	if inner == nil {
		d.log.Debug("not notifying: Telegram is disabled", "uid", uid)
		return nil
	}
	return inner.Notify(ctx, uid, text)
}

func (d *deferredNotifier) NotifyAdmins(ctx context.Context, text string) error {
	inner := d.get()
	if inner == nil {
		d.log.Debug("not notifying the admins: Telegram is disabled")
		return nil
	}
	return inner.NotifyAdmins(ctx, text)
}

// compareSubscriptions rebuilds every subscriber's bundle and diffs it against
// what is cached on disk, which is what the previous implementation wrote.
//
// This is the cutover check, and it deliberately writes nothing and starts
// nothing. Running the Go bot beside the Python one against the same data
// directory would have both refresh loops rewriting last_hash in subs.json with
// hashes that cannot agree -- each would conclude on every tick that the
// configuration had changed and message all six subscribers. So the comparison
// is a read, not a second bot.
//
// Compared semantically rather than byte for byte. The two languages render
// spacing and key order differently for no semantic reason, and the structural
// hash that drives notifications is computed over sorted keys, so byte equality
// would be false precision -- it would fail on differences no client can see
// while saying nothing about the ones that matter.
func compareSubscriptions(ctx context.Context, out io.Writer, parts *botParts) error {
	subscriptions, err := parts.store.Subscriptions()
	if err != nil {
		return err
	}
	if len(subscriptions) == 0 {
		fmt.Fprintln(out, "no subscriptions to compare")
		return nil
	}

	tokens := make([]string, 0, len(subscriptions))
	for token := range subscriptions {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)

	identical, differing, missing := 0, 0, 0
	for _, token := range tokens {
		uid := subscriptions[token].UID
		built, err := parts.svc.Bundle(ctx, uid, false)
		if err != nil {
			fmt.Fprintf(out, "uid %-12s FAILED to build: %v\n", uid, err)
			differing++
			continue
		}
		cached, found, err := parts.store.BundleCache(token)
		if err != nil {
			return err
		}
		if !found {
			fmt.Fprintf(out, "uid %-12s no cache to compare against (%d nodes built)\n",
				uid, countOutbounds(built))
			missing++
			continue
		}

		diff, err := diffBundles(cached, built)
		if err != nil {
			return err
		}
		if diff == "" {
			fmt.Fprintf(out, "uid %-12s identical (%d nodes)\n", uid, countOutbounds(built))
			identical++
			continue
		}
		fmt.Fprintf(out, "uid %-12s DIFFERS\n%s", uid, diff)
		differing++
	}

	fmt.Fprintf(out, "\n%d identical, %d differing, %d without a cache\n",
		identical, differing, missing)
	if differing > 0 {
		return fmt.Errorf("%d subscription(s) would change under their owner", differing)
	}
	return nil
}

// diffBundles reports how two bundles differ, by node tag.
//
// Per node rather than as one blob: a bundle is a list of independent methods,
// and "these two differ somewhere" is useless next to "the Mieru node gained a
// field and the WARP node is gone".
func diffBundles(before, after []byte) (string, error) {
	oldNodes, err := nodesByTag(before)
	if err != nil {
		return "", fmt.Errorf("parse the cached bundle: %w", err)
	}
	newNodes, err := nodesByTag(after)
	if err != nil {
		return "", fmt.Errorf("parse the rebuilt bundle: %w", err)
	}

	tags := map[string]bool{}
	for tag := range oldNodes {
		tags[tag] = true
	}
	for tag := range newNodes {
		tags[tag] = true
	}
	ordered := make([]string, 0, len(tags))
	for tag := range tags {
		ordered = append(ordered, tag)
	}
	sort.Strings(ordered)

	var report strings.Builder
	for _, tag := range ordered {
		oldNode, hadBefore := oldNodes[tag]
		newNode, hasNow := newNodes[tag]
		switch {
		case !hasNow:
			fmt.Fprintf(&report, "    - %s is gone\n", tag)
		case !hadBefore:
			fmt.Fprintf(&report, "    + %s is new\n", tag)
		case oldNode != newNode:
			fmt.Fprintf(&report, "    ~ %s changed\n      was %s\n      now %s\n",
				tag, oldNode, newNode)
		}
	}
	return report.String(), nil
}

// rotatingFields are blanked before comparing, because they are the fields the
// structural hash blanks too.
//
// The VK pool rotates hourly and the worker count moves with its size, and
// every client re-reads both on its own timer. Counting them as differences
// would report a change on every run while saying nothing about the ones a
// subscriber would have to act on -- which is the only question this
// comparison exists to answer.
var rotatingFields = []string{"vk_hashes", "workers"}

// nodesByTag renders each outbound in a canonical form, keyed by its tag, so
// two renderings of the same node compare equal.
func nodesByTag(bundle []byte) (map[string]string, error) {
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(parsed.Outbounds))
	for i, node := range parsed.Outbounds {
		tag, _ := node["tag"].(string)
		if tag == "" {
			tag = fmt.Sprintf("<untagged %d>", i)
		}
		for _, field := range rotatingFields {
			delete(node, field)
		}
		// Marshalling a map sorts its keys, which is the canonical form here.
		canonical, err := json.Marshal(node)
		if err != nil {
			return nil, err
		}
		out[tag] = string(canonical)
	}
	return out, nil
}

func countOutbounds(bundle []byte) int {
	nodes, err := nodesByTag(bundle)
	if err != nil {
		return 0
	}
	return len(nodes)
}

// describeBotConfig reports what the bot would run with, which is the cheapest
// way to tell a config file was picked up and read as intended.
func describeBotConfig(out io.Writer, cfg botcfg.Config) error {
	fmt.Fprintf(out, "core config      %s\n", cfg.Core.ConfigPath)
	fmt.Fprintf(out, "data directory   %s\n", cfg.Paths.DataDir)
	fmt.Fprintf(out, "public host      %s\n", cfg.Public.Host)
	fmt.Fprintf(out, "subscription     :%d  cf=%s  direct=%s\n",
		cfg.Subscription.Port, cfg.Subscription.HostCF, cfg.Subscription.HostDirect)
	fmt.Fprintf(out, "bundle           chains=%v awg3=%v skip=%v\n",
		cfg.Bundle.EnableChains, cfg.Bundle.EnableAWG3, cfg.Bundle.SkipTags)
	fmt.Fprintf(out, "intervals        refresh=%s hashcheck=%s notify=%s\n",
		cfg.Intervals.SubRefresh.Build(), cfg.Intervals.HashCheck.Build(),
		cfg.Intervals.NotifyPoll.Build())
	fmt.Fprintf(out, "admins           %v\n", cfg.Admins)
	fmt.Fprintf(out, "helpers          warp=%s checkhash=%s\n",
		cfg.Paths.WARPBinary, cfg.Paths.CheckHashBinary)
	if os.Getenv("TELEGRAM_TOKEN") == "" {
		fmt.Fprintln(out, "\nnote: TELEGRAM_TOKEN is not set, so only -no-telegram would start")
	}
	return nil
}

// joinHashes renders a list of call links for a message, one per line as code
// so an admin can copy one.
func joinHashes(hashes []string) string {
	var out string
	for _, hash := range hashes {
		out += "  `" + hash + "`\n"
	}
	return out
}

// runBotClaimCode issues the one-time code that adopts a bot with no admin.
// It is printed here and nowhere else: whoever can run this on the server is
// who should own the bot.
func runBotClaimCode(out io.Writer, args []string) error {
	fs := newFlagSet("bot claim-code", out)
	dataDir := fs.String("data-dir", discover.DefaultLayout().BotDataDir(), "the bot's data directory")
	ttl := fs.Duration("ttl", 15*time.Minute, "how long the code stays valid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ttl <= 0 || *ttl > 24*time.Hour {
		return fmt.Errorf("%w: claim-code takes -data-dir and a -ttl between 1s and 24h", ErrUsage)
	}
	store, err := state.New(*dataDir)
	if err != nil {
		return err
	}
	code, err := store.IssueClaim(*ttl, time.Now())
	if err != nil {
		return err
	}
	admins, _ := store.Admins()
	fmt.Fprintf(out, "claim code: %s\n\nSend this to the bot within %s:\n\n  /claim %s\n\n", code, ttl.Round(time.Second), code)
	fmt.Fprintf(out, "It works once, and %d wrong attempts destroy it.", state.MaxClaimAttempts)
	if len(admins) > 0 {
		fmt.Fprintf(out, " The bot already has %d admin(s); this adds one more.", len(admins))
	}
	fmt.Fprintln(out)
	return nil
}

// runBotGuide provisions one user on every method the bot offers and writes
// their connection guide. Run where the bot runs, with its configuration:
//
//	docker exec vpn-bot spaiter-vpn bot guide -config /etc/spaiter-vpn/bot.json -user alice -o /data/guide-alice.html
//
// runBotNotify is /notify from the server: one message to every approved user
// and admin, the APK button under it. It needs the same TELEGRAM_TOKEN the
// bot runs with and sends through the Bot API without polling, so it can run
// beside the live bot (`docker exec vpn-bot spaiter-vpn bot notify ...`).
func runBotNotify(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("bot notify", out)
	configPath := fs.String("config", "", "path to bot.json (defaults are this deployment's)")
	text := fs.String("text", "", "the message, in the bot's Markdown; \"-\" reads it from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: bot notify takes -text, not arguments", ErrUsage)
	}
	message := strings.TrimSpace(*text)
	if message == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("bot notify: read stdin: %w", err)
		}
		message = strings.TrimSpace(string(raw))
	}
	if message == "" {
		return fmt.Errorf("%w: bot notify needs -text (or -text - with the message on stdin)", ErrUsage)
	}
	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		return fmt.Errorf("%w: TELEGRAM_TOKEN is not set", ErrUsage)
	}
	cfg, err := botcfg.Load(*configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	parts, err := buildBot(cfg, log)
	if err != nil {
		return err
	}
	var options []tgbot.Option
	if cfg.TelegramAPIURL != "" {
		options = append(options, tgbot.WithServerURL(cfg.TelegramAPIURL))
	}
	client, err := tgbot.New(token, options...)
	if err != nil {
		return fmt.Errorf("bot notify: build the Telegram client: %w", err)
	}
	parts.face.Attach(client)
	sent, failed := parts.face.Broadcast(ctx, message)
	fmt.Fprintf(out, "notified %d user(s), %d failed\n", sent, failed)
	if failed > 0 && sent == 0 {
		return fmt.Errorf("bot notify: nothing was delivered")
	}
	return nil
}

func runBotGuide(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("bot guide", out)
	configPath := fs.String("config", "", "path to bot.json (defaults are this deployment's)")
	user := fs.String("user", "", "the account to provision and describe, as the core names it")
	output := fs.String("o", "", "where to write the HTML guide")
	bundleOut := fs.String("bundle-out", "", "also write the user's subscription bundle here, for `spaiter-vpn verify`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" || *output == "" || fs.NArg() != 0 {
		return fmt.Errorf("%w: bot guide needs -user and -o", ErrUsage)
	}
	cfg, err := botcfg.Load(*configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	parts, err := buildBot(cfg, log)
	if err != nil {
		return err
	}
	// One batch, one apply for everything the user is given.
	batch, done := parts.reloader.Begin(ctx)
	built, err := guide.Build(batch, parts.svc, parts.store, *user, time.Now())
	done()
	if err != nil {
		return err
	}
	html, err := guide.Render(built)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*output, html, 0o600); err != nil {
		return err
	}
	if *bundleOut != "" {
		if err := os.WriteFile(*bundleOut, built.Bundle, 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "wrote %s: %d methods for %s\n", *output, len(built.Methods), *user)
	return nil
}
