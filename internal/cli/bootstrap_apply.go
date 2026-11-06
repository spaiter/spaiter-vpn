package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/secret"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"github.com/spaiter/spaiter-vpn/internal/selftest"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
	"golang.org/x/term"
)

// discoverHost is indirected so the command's argument handling, consent and
// output can be tested without a real host. Production always uses the real
// read-only discovery.
var discoverHost = func(ctx context.Context, desired state.State, layout discover.Layout) (discover.Observed, error) {
	options := discover.DefaultOptions()
	options.Layout = layout
	return discover.Run(ctx, desired, options)
}

func runBootstrapPlan(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap plan", out)
	file := fs.String("f", "", "desired-state document (default: the stored one)")
	asJSON := fs.Bool("json", false, "print the machine-readable plan")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn bootstrap plan [-f FILE] [-json]\n\n")
		fmt.Fprintf(out, "Reads the host and prints what an apply would do. Writes nothing, pulls no\n")
		fmt.Fprintf(out, "image, refreshes no package metadata and generates no credential, so it is\n")
		fmt.Fprintf(out, "safe to run on a live server and can run unprivileged when the existing\n")
		fmt.Fprintf(out, "state is readable.\n\n")
		fmt.Fprintf(out, "Every action says whether it changes the host, why it exists, what proves it\n")
		fmt.Fprintf(out, "worked and what rollback is available. Secret values appear only as present,\n")
		fmt.Fprintf(out, "missing or invalid.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	desired, path, err := loadDesired(layout, *file)
	if err != nil {
		return err
	}
	built, err := buildPlan(ctx, desired, layout)
	if err != nil {
		return err
	}
	if *asJSON {
		data, err := built.MarshalIndent()
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	}
	writePlan(out, path, built)
	if built.Blocked {
		return fmt.Errorf("the plan is blocked; resolve the items above and run it again")
	}
	return nil
}

func buildPlan(ctx context.Context, desired state.State, layout discover.Layout) (plan.Plan, error) {
	observed, err := discoverHost(ctx, desired, layout)
	if err != nil {
		return plan.Plan{}, err
	}
	return plan.Build(desired, observed)
}

// writePlan prints the plan for a human. The disposition column is the part
// that matters: it separates what is only being checked from what will change
// the host.
func writePlan(out io.Writer, path string, built plan.Plan) {
	fmt.Fprintf(out, "desired state: %s\n", path)
	fmt.Fprintf(out, "mode:          %s\n", built.Mode)
	fmt.Fprintf(out, "digests:       desired %s / host %s\n\n", short(built.DesiredDigest), short(built.ObservationDigest))

	if len(built.Changes) > 0 {
		fmt.Fprintln(out, "changes against the stored intent:")
		for _, change := range built.Changes {
			fmt.Fprintf(out, "  %-10s %s: %v -> %v\n", change.Class, change.Path, change.Before, change.After)
		}
		fmt.Fprintln(out)
	}

	mutating := 0
	for _, action := range built.Actions {
		marker := " "
		if action.Mutates {
			marker = "*"
			mutating++
		}
		fmt.Fprintf(out, "%s %-9s %s\n", marker, action.Disposition, action.Summary)
		fmt.Fprintf(out, "      why:   %s\n", action.Reason)
		fmt.Fprintf(out, "      proof: %s\n", action.Proof)
		if action.Rollback != "" && action.Rollback != "none" {
			fmt.Fprintf(out, "      undo:  %s\n", action.Rollback)
		}
	}
	fmt.Fprintf(out, "\n%d actions, %d of which change this host (marked *)\n", len(built.Actions), mutating)
	if built.Blocked {
		fmt.Fprintln(out, "\nBLOCKED: apply is refused until the blocked items above are resolved.")
	}
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func runBootstrapApply(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap apply", out)
	file := fs.String("f", "", "desired-state document (default: the stored one)")
	yes := fs.Bool("yes", false, "apply without asking; required when stdin is not a terminal")
	strict := fs.Bool("strict", false, "treat preflight warnings as failures")
	singBoxBinary := fs.String("sing-box", "", "local sing-box binary to validate with instead of the image")
	defaults := health.DefaultOptions()
	deadline := fs.Duration("health-deadline", defaults.Deadline, "how long the started deployment has to become usable")
	settle := fs.Duration("health-settle", defaults.Settle, "how long it must stay usable before the generation is recorded")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn bootstrap apply [-f FILE] [-yes]\n\n")
		fmt.Fprintf(out, "Installs or converges the deployment: recompute the plan under an exclusive\n")
		fmt.Fprintf(out, "lock, check the host, generate, write the managed files in a recoverable\n")
		fmt.Fprintf(out, "transaction, open the missing firewall rules, start the project, wait for it\n")
		fmt.Fprintf(out, "to answer and run the self-test. Only then is the generation recorded.\n\n")
		fmt.Fprintf(out, "A failure undoes itself: the services this run started are stopped, the\n")
		fmt.Fprintf(out, "firewall rules it added are removed and the managed files are restored.\n")
		fmt.Fprintf(out, "Credentials, the core's cache and the bot's data are never deleted, so a\n")
		fmt.Fprintf(out, "retry does not rotate anybody's keys.\n\n")
		fmt.Fprintf(out, "Running it again converges the deployment instead of reinstalling it: the\n")
		fmt.Fprintf(out, "image, the bot's settings, log rotation and missing firewall rules are\n")
		fmt.Fprintf(out, "reconciled, while config.json and the client credentials are preserved.\n")
		fmt.Fprintf(out, "Supported config migrations recover every live server credential from\n")
		fmt.Fprintf(out, "config.json (including users added by the bot), re-render the new shape and\n")
		fmt.Fprintf(out, "apply it through the management API. A failure restores the previous file,\n")
		fmt.Fprintf(out, "re-applies it and waits for the previous deployment to answer again.\n\n")
		fmt.Fprintf(out, "Port, MTU, protocol-set and handshake changes are supported migrations.\n")
		fmt.Fprintf(out, "Subnet, tier, certificate, domain, XDP, log-level and seed-user changes\n")
		fmt.Fprintf(out, "remain blocked because they require peer reassignment, a full service\n")
		fmt.Fprintf(out, "restart or an explicit user policy. The blocked paths are printed.\n\n")
		fmt.Fprintf(out, "With bootstrap.installDocker, a host without Docker or Compose gets Docker's\n")
		fmt.Fprintf(out, "own packages at versions pinned in this binary, verified against an embedded\n")
		fmt.Fprintf(out, "repository key, before preflight. Packages are never removed automatically;\n")
		fmt.Fprintf(out, "what was installed is recorded and shown by `bootstrap status`.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}

	// Consent first, before anything is read or run. Stdin not being a terminal
	// is not consent: a plan nobody saw is not a plan anybody approved.
	if !*yes && !term.IsTerminal(int(os.Stdin.Fd())) {
		// A plain error rather than ErrUsage: nothing was mistyped, so dumping
		// the whole command list would bury the one sentence that matters.
		return errors.New("stdin is not a terminal, so there is nobody to confirm the plan.\n" +
			"Review it with `spaiter-vpn bootstrap plan`, then apply with -yes.")
	}
	if os.Geteuid() != 0 {
		// Printed rather than attempted. A tool that elevates itself hides the
		// moment at which the operator agreed to give it root.
		return fmt.Errorf("apply writes /etc, changes firewall rules and runs the self-test, so it needs root:\n\n  sudo %s\n", strings.Join(append([]string{selfPathOrName(), "bootstrap", "apply"}, args...), " "))
	}

	desired, path, err := loadDesired(layout, *file)
	if err != nil {
		return err
	}

	// Recover BEFORE planning, not as part of applying.
	//
	// The acceptance run found this the hard way: an apply killed after its
	// files were written left config.json, secrets.json and the compose file on
	// disk with no receipt naming them. The transaction manager rolls such a
	// transaction back whenever the lock is taken — but the CLI planned first,
	// and the planner saw that half-written state as a deployment it must not
	// adopt. So the plan came back blocked, apply never ran, the lock was never
	// taken, and the host could not heal through the normal path at all. It
	// needed `rm -rf` to become installable again.
	//
	// Separate from the apply engine's own lock on purpose: a recovery that
	// happens inside apply.Run is too late to inform the plan the operator is
	// about to read. The window between this and that lock is covered by the
	// engine recomputing the plan and refusing a digest that has since changed.
	if err := newTransactionManager(layout).Recover(); err != nil {
		return fmt.Errorf("recover an interrupted transaction: %w", err)
	}

	approved, err := buildPlan(ctx, desired, layout)
	if err != nil {
		return err
	}
	writePlan(out, path, approved)
	if approved.Blocked {
		return fmt.Errorf("the plan is blocked; resolve the items above and run it again")
	}
	if !*yes {
		confirmed, err := confirm(out, "\nApply this plan? Type yes to continue: ")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "nothing was changed")
			return nil
		}
	}

	if *deadline <= 0 || *settle < 0 || *settle >= *deadline {
		return fmt.Errorf("%w: -health-settle must be shorter than -health-deadline and neither may be negative", ErrUsage)
	}
	options, err := applyOptions(ctx, layout, desired, approved, out, *strict, *singBoxBinary)
	if err != nil {
		return err
	}
	options.HealthTuning = health.Options{Deadline: *deadline, Settle: *settle}
	result, err := apply.Run(ctx, options)
	if err != nil {
		return err
	}
	writeResult(out, layout, desired, approved, result)
	return nil
}

// applyOptions wires the engine to the real host.
func applyOptions(ctx context.Context, layout discover.Layout, desired state.State, approved plan.Plan, out io.Writer, strict bool, singBoxBinary string) (apply.Options, error) {
	store := secret.Store{Dir: layout.CredentialDir()}
	env := map[string]string{}
	if desired.Bot.Enabled {
		// Through the process environment, never the generated .env: that file
		// is 0644 and deliberately carries no secret.
		token, err := store.Read(desired.Bot.TelegramToken)
		if err != nil {
			return apply.Options{}, err
		}
		env["TELEGRAM_TOKEN"] = token
	}

	var runner compose.Runner
	var check func(context.Context, []byte) error
	if installsDocker(approved) {
		// Nothing to detect yet: the engine installs Docker before it first
		// validates a config or calls Compose.
		runner = &lazyCompose{env: env}
		check = lazyCheck(singBoxBinary, desired.Deployment.Image, out)
	} else {
		checker, err := singbox.Detect(ctx, singBoxBinary, desired.Deployment.Image)
		if err != nil {
			if errors.Is(err, singbox.ErrUnavailable) {
				return apply.Options{}, fmt.Errorf("%w\n\nValidation is not optional here: a config the generator accepted but sing-box will not start is a server that comes up dead. Pass -sing-box <path> to use a local binary", err)
			}
			return apply.Options{}, err
		}
		fmt.Fprintf(out, "\nvalidating generated configuration with %s\n", checker.Describe())
		check = checker.Check
		detected, err := compose.Detect(ctx)
		if err != nil {
			return apply.Options{}, err
		}
		runner = detected
		if len(env) > 0 {
			runner = detected.WithEnvironment(env)
		}
	}

	// Constructed unconditionally but used only for rules the plan says are
	// missing. When it cannot be built, apply refuses rather than starting a
	// deployment that is reachable by nobody.
	applier, _ := firewall.NewUFWApplier()

	return apply.Options{
		Layout:   layout,
		Desired:  desired,
		Approved: approved,
		Discover: func(ctx context.Context, desired state.State) (discover.Observed, error) {
			return discoverHost(ctx, desired, layout)
		},
		Secrets:       store,
		Compose:       runner,
		CheckConfig:   check,
		Preflight:     preflight.Run,
		Strict:        strict,
		SingBoxBinary: singBoxBinary,
		Firewall:      applier,
		SelfTest: func(ctx context.Context, out io.Writer) error {
			options := selftest.DefaultOptions()
			options.ConfigPath = layout.ConfigPath()
			_, err := selftest.Run(ctx, out, options)
			return err
		},
		Manager: newTransactionManager(layout),
		Out:     out,
	}, nil
}

func installsDocker(approved plan.Plan) bool {
	for _, action := range approved.Actions {
		if (action.ID == "docker-install" || action.ID == "docker-compose-install") && action.Disposition == plan.Apply {
			return true
		}
	}
	return false
}

// writeResult ends with the checks that cannot be proved from this host. Saying
// "healthy" without them would be a claim about the internet made from inside
// the machine.
func writeResult(out io.Writer, layout discover.Layout, desired state.State, approved plan.Plan, result *apply.Result) {
	fmt.Fprintf(out, "\napplied: transaction %s, %d managed files\n", result.Transaction, len(result.Files))
	if result.Health != nil {
		fmt.Fprintf(out, "healthy after %s (%d samples)\n", result.Health.Waited.Truncate(1e6), result.Health.Samples)
	}
	for _, rule := range result.FirewallAdded {
		fmt.Fprintf(out, "opened %s on the host firewall\n", rule)
	}

	fmt.Fprintf(out, "\nClient credentials: %s (mode 0600)\n", layout.SecretsPath())
	fmt.Fprintf(out, "Render importable configs with:\n  spaiter-vpn clients -secrets %s -host <public address>\n", layout.SecretsPath())

	fmt.Fprintln(out, "\nStill unproven from this host:")
	for _, action := range approved.Actions {
		if action.Disposition == plan.Manual {
			fmt.Fprintf(out, "  - %s: %s\n", action.Summary, action.Proof)
		}
	}
	spec, err := desired.PreflightSpec(nil)
	if err == nil {
		var ports []string
		for _, rule := range discover.FirewallRules(desired, spec) {
			ports = append(ports, rule.String())
		}
		fmt.Fprintf(out, "  - a provider firewall must allow: %s\n", strings.Join(ports, " "))
	}
	fmt.Fprintf(out, "\nFrom another network, run:\n  spaiter-vpn probe -secrets <copy of secrets.json> -host <public address>\n")
	// Said after every apply, because a backup taken once goes stale with the
	// first user the bot adds, and because the provider's own snapshots are not
	// one: they are lost with the account, and a hoster's have been wiped in a
	// breach.
	fmt.Fprintf(out, "\nKeep an encrypted backup somewhere other than this provider:\n  ssh <this server> sudo spaiter-vpn backup -recipient <age1...> > vpn-backup.age\n")
}

func confirm(out io.Writer, prompt string) (bool, error) {
	fmt.Fprint(out, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("read the confirmation: %w", err)
	}
	// Only an explicit "yes". A bare enter, "y" by reflex or a stray character
	// must not install a VPN server.
	return strings.EqualFold(strings.TrimSpace(line), "yes"), nil
}

func selfPathOrName() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	return "spaiter-vpn"
}
