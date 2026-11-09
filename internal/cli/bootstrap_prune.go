package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
)

func runBootstrapPrune(_ context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap prune", out)
	keep := fs.Int("keep", 0, "number of committed generations to retain, including current (minimum 2)")
	yes := fs.Bool("yes", false, "delete selected transactions; without it, only preview the pruning")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: spaiter-vpn bootstrap prune -keep N [-yes]")
		fmt.Fprintln(out, "\nDeletes transaction journals and backups older than the retained committed")
		fmt.Fprintln(out, "generations. N includes the current generation and must be at least 2, so")
		fmt.Fprintln(out, "the previous generation remains available for rollback. Recovery runs first,")
		fmt.Fprintln(out, "and the operation holds the same exclusive lock as apply and rollback.")
		fmt.Fprintln(out, "\nWithout -yes, prints the selected transactions and deletes nothing.")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: prune takes flags only", ErrUsage)
	}
	if *keep < transaction.MinimumRetainedGenerations {
		return fmt.Errorf("%w: -keep is required and must be at least %d", ErrUsage, transaction.MinimumRetainedGenerations)
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if !runningAsRoot() {
		return fmt.Errorf("prune deletes root-owned transaction history, so it needs root:\n\n  sudo %s\n", strings.Join(append([]string{selfPathOrName(), "bootstrap", "prune"}, args...), " "))
	}

	result, err := newTransactionManager(layout).Prune(*keep, !*yes)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "retention: %d committed generation(s), including current and previous\n", *keep)
	fmt.Fprintf(out, "retained:  %d committed generation(s)\n", len(result.Retained))
	fmt.Fprintf(out, "selected:  %d transaction(s)\n", len(result.Selected))
	for _, selected := range result.Selected {
		fmt.Fprintf(out, "  sequence %d: %s (%s)\n", selected.Sequence, selected.Transaction, selected.Status)
	}
	if result.DryRun {
		fmt.Fprintln(out, "\npreview only: nothing was deleted; rerun with -yes to apply this retention rule")
	} else {
		fmt.Fprintf(out, "\npruned %d transaction(s); retained rollback points remain usable\n", len(result.Selected))
	}
	return nil
}
