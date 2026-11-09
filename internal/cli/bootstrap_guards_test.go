package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// With root pretended, the commands get past their guards and must stop at the
// first thing that is genuinely missing, not crash or touch anything.
func TestRootCommandsStopCleanlyAtTheirFirstMissingPrerequisite(t *testing.T) {
	pretendRoot(t, true)
	ctx := context.Background()

	t.Run("apply without a desired state", func(t *testing.T) {
		_, args := statusLayout(t)
		err := runBootstrapApply(ctx, &bytes.Buffer{}, append([]string{"-yes"}, args...))
		if err == nil {
			t.Fatal("apply without a desired state succeeded")
		}
	})
	t.Run("apply rejects incoherent health timings", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("a real root would go on to plan against this host")
		}
		layout, args := statusLayout(t)
		writeDesired(t, layout, state.Default([]string{"owner"}))
		err := runBootstrapApply(ctx, &bytes.Buffer{}, append([]string{"-yes", "-health-settle", "9h"}, args...))
		if err == nil {
			t.Fatal("incoherent timings accepted")
		}
	})
	t.Run("rollback without history", func(t *testing.T) {
		_, args := statusLayout(t)
		if err := runBootstrapRollback(ctx, &bytes.Buffer{}, append([]string{"-yes"}, args...)); err == nil {
			t.Fatal("rollback with no history succeeded")
		}
	})
	t.Run("rotate without a desired state", func(t *testing.T) {
		_, args := statusLayout(t)
		if err := runBootstrapRotate(ctx, &bytes.Buffer{}, append([]string{"-yes", "-users", "owner"}, args...)); err == nil {
			t.Fatal("rotate without a desired state succeeded")
		}
	})
	t.Run("prune on a fresh host", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("the transaction manager owns its directory as root")
		}
		_, args := statusLayout(t)
		var out bytes.Buffer
		if err := runBootstrapPrune(ctx, &out, append([]string{"-keep", "2"}, args...)); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "preview only") {
			t.Errorf("a prune without -yes deleted: %s", out.String())
		}
	})
}

func TestApplyAndRollbackRefuseWithoutRootEvenWhenAskedToConfirm(t *testing.T) {
	pretendRoot(t, false)
	_, args := statusLayout(t)
	for name, run := range map[string]func([]string) error{
		"apply":    func(a []string) error { return runBootstrapApply(context.Background(), &bytes.Buffer{}, a) },
		"rollback": func(a []string) error { return runBootstrapRollback(context.Background(), &bytes.Buffer{}, a) },
		"rotate":   func(a []string) error { return runBootstrapRotate(context.Background(), &bytes.Buffer{}, a) },
		"prune": func(a []string) error {
			return runBootstrapPrune(context.Background(), &bytes.Buffer{}, a)
		},
	} {
		extra := []string{"-yes", "-users", "a", "-keep", "2"}
		if name == "apply" || name == "rollback" {
			extra = []string{"-yes"}
		} else if name == "prune" {
			extra = []string{"-keep", "2"}
		} else {
			extra = []string{"-yes", "-users", "a"}
		}
		err := run(append(extra, args...))
		if err == nil || !strings.Contains(err.Error(), "needs root") || !strings.Contains(err.Error(), "sudo ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
