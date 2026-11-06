package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"sort"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// runBootstrapStatus answers "what is installed, and is it working".
//
// Two separate questions, reported separately: what the last apply recorded,
// and what the host is doing right now. Collapsing them would hide the case
// that matters — a recorded generation whose services have since died.
func runBootstrapStatus(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap status", out)
	layoutOpts.register(fs)
	probe := fs.Bool("probe", true, "also ask the running core's management endpoint")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn bootstrap status\n\n")
		fmt.Fprintf(out, "Prints the stored operator intent, the generation the last apply recorded,\n")
		fmt.Fprintf(out, "and what the compose project is doing now. Read-only.\n\n")
		fmt.Fprintf(out, "The management probe needs to read the root-owned config, so without root\n")
		fmt.Fprintf(out, "that line reports why it could not be answered rather than claiming health.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "config root: %s\ndata root:   %s\n\n", layout.ConfigRoot, layout.DataRoot)

	desired, err := state.Load(layout.DesiredPath())
	switch {
	case err == nil:
		digest, digestErr := desired.Digest()
		if digestErr != nil {
			return digestErr
		}
		fmt.Fprintf(out, "stored intent: %s\n", layout.DesiredPath())
		fmt.Fprintf(out, "  digest:  %s\n", short(digest))
		fmt.Fprintf(out, "  tier:    %s\n", desired.Deployment.Tier)
		fmt.Fprintf(out, "  image:   %s\n", desired.Deployment.Image)
		fmt.Fprintf(out, "  users:   %d seeded\n", len(desired.Bootstrap.SeedUsers))
		fmt.Fprintf(out, "  bot:     %t\n", desired.Bot.Enabled)
	// errors.Is, not os.IsNotExist: state.Load wraps the open error, and
	// os.IsNotExist does not see through %w — which made a host with nothing
	// installed report its intent as UNREADABLE.
	case errors.Is(err, iofs.ErrNotExist):
		fmt.Fprintf(out, "stored intent: none at %s\n", layout.DesiredPath())
	default:
		// An unreadable or invalid document is reported, not treated as
		// absent: "nothing is installed" and "what is installed cannot be
		// understood" need different reactions.
		fmt.Fprintf(out, "stored intent: UNREADABLE at %s: %v\n", layout.DesiredPath(), err)
	}

	manager := newTransactionManager(layout)
	receipt, present, err := manager.Current()
	switch {
	case err != nil:
		fmt.Fprintf(out, "\nlast apply:    UNREADABLE receipt: %v\n", err)
	case !present:
		fmt.Fprintf(out, "\nlast apply:    none recorded\n")
	default:
		fmt.Fprintf(out, "\nlast apply:    generation %d, transaction %s\n", receipt.Sequence, receipt.Transaction)
		paths := make([]string, 0, len(receipt.Files))
		for path := range receipt.Files {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			file := receipt.Files[path]
			fmt.Fprintf(out, "  %-14s %04o  %s\n", file.Ownership, file.Mode, path)
		}
	}

	switch record, recordErr := dockerinstall.ReadRecord(layout.PlatformRecordPath()); {
	case recordErr != nil:
		fmt.Fprintf(out, "\nhost packages: UNREADABLE record: %v\n", recordErr)
	case record != nil:
		fmt.Fprintf(out, "\nhost packages: installed by bootstrap on %s (%s); removal is yours to decide\n", record.InstalledAt.Format("2006-01-02"), record.Release)
		names := make([]string, 0, len(record.Packages))
		for name := range record.Packages {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(out, "  %s=%s\n", name, record.Packages[name])
		}
		for _, path := range record.Files {
			fmt.Fprintf(out, "  %s\n", path)
		}
	}

	if _, statErr := os.Stat(layout.ComposePath()); statErr != nil {
		fmt.Fprintf(out, "\nservices:      no compose project at %s\n", layout.ComposePath())
		return nil
	}
	return reportServices(ctx, out, layout, err == nil && *probe)
}

func reportServices(ctx context.Context, out io.Writer, layout discover.Layout, withProbe bool) error {
	runner, err := compose.Detect(ctx)
	if err != nil {
		fmt.Fprintf(out, "\nservices:      cannot be read: %v\n", err)
		return nil
	}
	states, err := runner.Services(ctx, layout.ComposePath())
	if err != nil {
		fmt.Fprintf(out, "\nservices:      cannot be read: %v\n", err)
		return nil
	}
	fmt.Fprintln(out, "\nservices:")
	if len(states) == 0 {
		fmt.Fprintln(out, "  none; the project is not running")
	}
	for _, service := range states {
		verdict := "running"
		if !service.Running() {
			verdict = service.State
			if service.Health != "" {
				verdict += "/" + service.Health
			}
		}
		fmt.Fprintf(out, "  %-16s %s\n", service.Service, verdict)
	}

	if !withProbe {
		return nil
	}
	// One sample, not a wait: status reports what is true now, while the wait
	// is for deciding whether an apply succeeded.
	client, err := manage.NewFromCoreConfig(layout.ConfigPath())
	if err != nil {
		fmt.Fprintf(out, "\nmanagement:    not answered: %v\n", err)
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Version(probeCtx); err != nil {
		fmt.Fprintf(out, "\nmanagement:    NOT ANSWERING: %v\n", err)
		fmt.Fprintf(out, "               a running container is not proof the core loaded its configuration\n")
		return nil
	}
	fmt.Fprintln(out, "\nmanagement:    answering on loopback")
	return nil
}
