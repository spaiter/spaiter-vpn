package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func runBootstrapRotate(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap rotate", out)
	users := fs.String("users", "", "comma-separated users whose credentials to reissue")
	yes := fs.Bool("yes", false, "rotate without asking; required when stdin is not a terminal")
	strict := fs.Bool("strict", false, "treat preflight warnings as failures")
	singBoxBinary := fs.String("sing-box", "", "local sing-box binary to validate with instead of the image")
	defaults := health.DefaultOptions()
	deadline := fs.Duration("health-deadline", defaults.Deadline, "how long the rotated deployment has to become usable")
	settle := fs.Duration("health-settle", defaults.Settle, "how long it must stay usable before the generation is recorded")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: spaiter-vpn bootstrap rotate -users alice[,bob] [-yes]")
		fmt.Fprintln(out, "\nReissues every per-user credential of the named users as a new generation:")
		fmt.Fprintln(out, "proxy accounts, WireGuard peer keypairs (addresses are kept), the WG-over-VK")
		fmt.Fprintln(out, "relay password and the bot subscription token. Their existing client")
		fmt.Fprintln(out, "configurations and subscription links stop working; seed users get the new")
		fmt.Fprintln(out, "values in secrets.json, bot users from the bot. Every other user and every")
		fmt.Fprintln(out, "deployment-wide key is left alone, and the apply proves it before writing.")
		fmt.Fprintln(out, "\nThe request is recorded in desired.json as migrationPolicy.rotateCredentials")
		fmt.Fprintln(out, "with a fresh id, so it is reviewable afterwards and never repeats by itself.")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: rotate takes flags only", ErrUsage)
	}
	selected, err := parseRotationUsers(*users)
	if err != nil {
		return err
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if !*yes && !promptIsTerminal() {
		return errors.New("stdin is not a terminal, so there is nobody to confirm the rotation.\n" +
			"Review the printed plan interactively, or run again with -yes.")
	}
	if !runningAsRoot() {
		return fmt.Errorf("rotate writes /etc and the bot's state and runs the self-test, so it needs root:\n\n  sudo %s\n", strings.Join(append([]string{selfPathOrName(), "bootstrap", "rotate"}, args...), " "))
	}
	if *deadline <= 0 || *settle < 0 || *settle >= *deadline {
		return fmt.Errorf("%w: -health-settle must be shorter than -health-deadline and neither may be negative", ErrUsage)
	}

	manager := newTransactionManager(layout)
	if err := manager.Recover(); err != nil {
		return fmt.Errorf("recover an interrupted transaction: %w", err)
	}
	if _, exists, err := manager.Current(); err != nil {
		return err
	} else if !exists {
		return errors.New("there is no committed generation whose users could be rotated")
	}
	current, err := state.Load(layout.DesiredPath())
	if err != nil {
		return fmt.Errorf("read current desired state: %w", err)
	}
	id, err := newRotationID(time.Now())
	if err != nil {
		return err
	}
	desired, err := rotationDesired(current, selected, id)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "rotation %s: %s\n", id, strings.Join(selected, ", "))
	fmt.Fprintln(out, "effect:   these users' current client configurations and subscription links stop working")
	fmt.Fprintln(out, "result:   a new generation; a later rollback restores intent, not these credentials")
	fmt.Fprintln(out)
	approved, err := buildPlan(ctx, desired, layout)
	if err != nil {
		return err
	}
	writePlan(out, "rotation "+id, approved)
	if approved.Blocked {
		return errors.New("the rotation plan is blocked; no host changes were made")
	}
	if !*yes {
		confirmed, err := confirm(out, "\nReissue these credentials? Type yes to continue: ")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "nothing was changed")
			return nil
		}
	}

	options, err := buildApplyOptions(ctx, layout, desired, approved, out, *strict, *singBoxBinary)
	if err != nil {
		return err
	}
	options.HealthTuning = health.Options{Deadline: *deadline, Settle: *settle}
	applyResult, err := runRollbackApply(ctx, options)
	if err != nil {
		return err
	}
	writeResult(out, layout, desired, approved, applyResult)
	fmt.Fprintf(out, "\nrotation %s committed as transaction %s\n", id, applyResult.Transaction)
	seed := make([]string, 0, len(selected))
	for _, name := range selected {
		if slices.Contains(desired.Bootstrap.SeedUsers, name) {
			seed = append(seed, name)
		}
	}
	if len(seed) > 0 {
		fmt.Fprintf(out, "new client credentials for %s are in %s\n", strings.Join(seed, ", "), layout.SecretsPath())
	}
	if desired.Bot.Enabled {
		fmt.Fprintln(out, "bot users fetch their new configuration and subscription link from the bot")
	}
	return nil
}

func parseRotationUsers(raw string) ([]string, error) {
	var users []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if slices.Contains(users, name) {
			return nil, fmt.Errorf("%w: -users names %q twice", ErrUsage, name)
		}
		users = append(users, name)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%w: -users is required", ErrUsage)
	}
	slices.Sort(users)
	return users, nil
}

// newRotationID is sortable and unique without coordination: the time says
// when it was asked for, the suffix separates two requests in one second.
func newRotationID(now time.Time) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("generate a rotation id: %w", err)
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix), nil
}

// rotationDesired is the current intent plus a rotation request. Every other
// policy entry is kept as the audit record it already is.
func rotationDesired(current state.State, users []string, id string) (state.State, error) {
	desired := current
	policy := cloneRollbackPolicy(current.MigrationPolicy)
	if policy == nil {
		policy = &state.MigrationPolicy{}
	}
	if len(policy.Subnets) == 0 {
		policy.Subnets = nil
	}
	policy.RotateCredentials = &state.CredentialRotation{ID: id, Users: users, Strategy: state.CredentialRotationStrategyReissue}
	desired.MigrationPolicy = policy
	if err := desired.Validate(); err != nil {
		return state.State{}, fmt.Errorf("synthesized rotation state: %w", err)
	}
	return desired, nil
}
