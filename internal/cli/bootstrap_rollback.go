package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"golang.org/x/term"
)

func runBootstrapRollback(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap rollback", out)
	generation := fs.Uint64("generation", 0, "committed generation to restore (default: previous)")
	yes := fs.Bool("yes", false, "rollback without asking; required when stdin is not a terminal")
	strict := fs.Bool("strict", false, "treat preflight warnings as failures")
	singBoxBinary := fs.String("sing-box", "", "local sing-box binary to validate with instead of the image")
	defaults := health.DefaultOptions()
	deadline := fs.Duration("health-deadline", defaults.Deadline, "how long the restored deployment has to become usable")
	settle := fs.Duration("health-settle", defaults.Settle, "how long it must stay usable before the generation is recorded")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: spaiter-vpn bootstrap rollback [-generation N] [-yes]")
		fmt.Fprintln(out, "\nRestores deployment intent from an earlier successful generation as a new,")
		fmt.Fprintln(out, "monotonic transaction. The default is the previous committed generation.")
		fmt.Fprintln(out, "Current seed users, bot-provisioned users and all live credentials survive;")
		fmt.Fprintln(out, "subnet addresses are migrated by host identity. The normal preflight, file")
		fmt.Fprintln(out, "transaction, firewall reconciliation, health gate and self-test all run.")
		fmt.Fprintln(out, "\nRollback refuses to re-enable a protocol absent from the current deployment,")
		fmt.Fprintln(out, "because doing that would silently mint replacement client credentials.")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: rollback takes flags only", ErrUsage)
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if !*yes && !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("stdin is not a terminal, so there is nobody to confirm the rollback.\n" +
			"Review the printed plan interactively, or run again with -yes.")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("rollback writes /etc, changes firewall rules and runs the self-test, so it needs root:\n\n  sudo %s\n", strings.Join(append([]string{selfPathOrName(), "bootstrap", "rollback"}, args...), " "))
	}
	if *deadline <= 0 || *settle < 0 || *settle >= *deadline {
		return fmt.Errorf("%w: -health-settle must be shorter than -health-deadline and neither may be negative", ErrUsage)
	}

	desired, target, err := synthesizeRollback(layout, *generation)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "rollback target: generation %d (%s), committed %s\n", target.Sequence, target.Transaction, target.CommittedAt.Format("2006-01-02 15:04:05Z"))
	fmt.Fprintln(out, "preserved:       current seed users, bot users, credentials and runtime data")
	fmt.Fprintln(out, "result:          a new generation; committed history is never rewritten")
	fmt.Fprintln(out)
	approved, err := buildPlan(ctx, desired, layout)
	if err != nil {
		return err
	}
	writePlan(out, fmt.Sprintf("generation %d (rollback synthesis)", target.Sequence), approved)
	if approved.Blocked {
		return errors.New("the rollback plan is blocked; no host changes were made")
	}
	if !*yes {
		confirmed, err := confirm(out, "\nApply this rollback as a new generation? Type yes to continue: ")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "nothing was changed")
			return nil
		}
	}

	options, err := applyOptions(ctx, layout, desired, approved, out, *strict, *singBoxBinary)
	if err != nil {
		return err
	}
	options.HealthTuning = health.Options{Deadline: *deadline, Settle: *settle}
	// The history was read before planning, exactly like apply reads desired
	// state before taking its engine lock. apply.Run recomputes discovery under
	// that lock and rejects any observation digest that changed in the gap.
	applyResult, err := runRollbackApply(ctx, options)
	if err != nil {
		return err
	}
	writeResult(out, layout, desired, approved, applyResult)
	fmt.Fprintf(out, "\nrollback of generation %d committed as transaction %s\n", target.Sequence, applyResult.Transaction)
	return nil
}

// synthesizeRollback recovers interrupted work, selects the generation and
// builds the desired state a rollback to it applies. Shared by the CLI and the
// control daemon, so both refuse exactly the same rollbacks.
func synthesizeRollback(layout discover.Layout, requested uint64) (state.State, transaction.Generation, error) {
	manager := newTransactionManager(layout)
	if err := manager.Recover(); err != nil {
		return state.State{}, transaction.Generation{}, fmt.Errorf("recover an interrupted transaction: %w", err)
	}
	currentReceipt, exists, err := manager.Current()
	if err != nil {
		return state.State{}, transaction.Generation{}, err
	}
	if !exists {
		return state.State{}, transaction.Generation{}, errors.New("there is no committed generation to roll back")
	}
	current, err := state.Load(layout.DesiredPath())
	if err != nil {
		return state.State{}, transaction.Generation{}, fmt.Errorf("read current desired state: %w", err)
	}
	generations, err := manager.Generations()
	if err != nil {
		return state.State{}, transaction.Generation{}, fmt.Errorf("read committed generations: %w", err)
	}
	target, err := selectRollbackGeneration(generations, currentReceipt.Sequence, requested)
	if err != nil {
		return state.State{}, transaction.Generation{}, err
	}
	raw, err := manager.GenerationFile(target.Sequence, layout.DesiredPath())
	if err != nil {
		return state.State{}, transaction.Generation{}, fmt.Errorf("restore desired state from generation %d: %w", target.Sequence, err)
	}
	historical, err := state.Parse(raw)
	if err != nil {
		return state.State{}, transaction.Generation{}, fmt.Errorf("generation %d contains an invalid desired state: %w", target.Sequence, err)
	}
	desired, err := rollbackDesired(current, historical)
	if err != nil {
		return state.State{}, transaction.Generation{}, err
	}
	return desired, target, nil
}

// runRollbackApply is a small seam kept separate from synthesis tests.
func runRollbackApply(ctx context.Context, options apply.Options) (*apply.Result, error) {
	return apply.Run(ctx, options)
}

func selectRollbackGeneration(generations []transaction.Generation, current, requested uint64) (transaction.Generation, error) {
	wanted := requested
	if wanted == 0 {
		for _, generation := range generations {
			if generation.Sequence < current && generation.Sequence > wanted {
				wanted = generation.Sequence
			}
		}
		if wanted == 0 {
			return transaction.Generation{}, errors.New("there is no earlier committed generation to roll back to")
		}
	}
	if wanted >= current {
		return transaction.Generation{}, fmt.Errorf("rollback generation %d must be older than current generation %d", wanted, current)
	}
	for _, generation := range generations {
		if generation.Sequence == wanted {
			return generation, nil
		}
	}
	return transaction.Generation{}, fmt.Errorf("committed generation %d does not exist", wanted)
}

func rollbackDesired(current, historical state.State) (state.State, error) {
	desired := historical
	desired.Bootstrap.SeedUsers = append([]string(nil), current.Bootstrap.SeedUsers...)
	desired.Bot.WDTTConfigDirectory = current.Bot.WDTTConfigDirectory

	policy := cloneRollbackPolicy(current.MigrationPolicy)
	if policy == nil {
		policy = &state.MigrationPolicy{}
	}
	if policy.Subnets == nil {
		policy.Subnets = map[profile.Protocol]state.SubnetMigration{}
	}
	for protocol, from := range current.Deployment.Subnets {
		to := desired.Deployment.Subnets[protocol]
		if from != to {
			policy.Subnets[protocol] = state.SubnetMigration{From: from, To: to, Strategy: state.SubnetStrategyPreserveHost}
		}
	}
	if len(policy.Subnets) == 0 {
		// Absent, not empty: an empty subnets object is invalid, and a rollback
		// that moves no subnet may still carry other audit records.
		policy.Subnets = nil
	}
	if len(policy.Subnets) == 0 && policy.SeedUsers == nil && policy.RotateCredentials == nil {
		desired.MigrationPolicy = nil
	} else {
		desired.MigrationPolicy = policy
	}

	currentSpec, err := current.PreflightSpec(nil)
	if err != nil {
		return state.State{}, fmt.Errorf("read current protocol set: %w", err)
	}
	targetSpec, err := desired.PreflightSpec(nil)
	if err != nil {
		return state.State{}, fmt.Errorf("build rollback protocol set: %w", err)
	}
	enabled := map[profile.Protocol]bool{}
	for _, protocol := range currentSpec.EnabledProtocols() {
		enabled[protocol] = true
	}
	var missing []string
	for _, protocol := range targetSpec.EnabledProtocols() {
		if !enabled[protocol] {
			missing = append(missing, string(protocol))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return state.State{}, fmt.Errorf("rollback would re-enable protocols absent from the current deployment (%s), which could mint replacement client credentials; first migrate those protocols explicitly", strings.Join(missing, ", "))
	}
	if err := desired.Validate(); err != nil {
		return state.State{}, fmt.Errorf("synthesized rollback state: %w", err)
	}
	return desired, nil
}

func cloneRollbackPolicy(in *state.MigrationPolicy) *state.MigrationPolicy {
	if in == nil {
		return nil
	}
	out := &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{}}
	for protocol, migration := range in.Subnets {
		out.Subnets[protocol] = migration
	}
	if in.SeedUsers != nil {
		out.SeedUsers = &state.SeedUsersMigration{
			From: append([]string(nil), in.SeedUsers.From...), To: append([]string(nil), in.SeedUsers.To...), Strategy: in.SeedUsers.Strategy,
		}
	}
	// Carried verbatim so it stays the current generation's audit record: a
	// rollback restores intent, and must neither repeat a rotation nor bring
	// back the credentials one retired.
	if in.RotateCredentials != nil {
		out.RotateCredentials = &state.CredentialRotation{
			ID: in.RotateCredentials.ID, Users: append([]string(nil), in.RotateCredentials.Users...), Strategy: in.RotateCredentials.Strategy,
		}
	}
	return out
}
