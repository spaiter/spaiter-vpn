package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func ownTransactions(t *testing.T) {
	t.Helper()
	old := managerOwner
	managerOwner.UID, managerOwner.GID = uint32(os.Getuid()), uint32(os.Getgid())
	t.Cleanup(func() { managerOwner = old })
}

func TestBootstrapCommandsExplainThemselvesOnHelp(t *testing.T) {
	for name, run := range map[string]func(context.Context, *bytes.Buffer, []string) error{
		"apply": func(ctx context.Context, out *bytes.Buffer, a []string) error { return runBootstrapApply(ctx, out, a) },
		"rollback": func(ctx context.Context, out *bytes.Buffer, a []string) error {
			return runBootstrapRollback(ctx, out, a)
		},
		"rotate": func(ctx context.Context, out *bytes.Buffer, a []string) error { return runBootstrapRotate(ctx, out, a) },
		"prune":  func(ctx context.Context, out *bytes.Buffer, a []string) error { return runBootstrapPrune(ctx, out, a) },
	} {
		var out bytes.Buffer
		if err := run(context.Background(), &out, []string{"-h"}); err == nil {
			t.Errorf("%s -h reported success", name)
		}
		if !strings.Contains(out.String(), "usage: spaiter-vpn bootstrap "+name) {
			t.Errorf("%s -h printed:\n%s", name, out.String())
		}
	}
}

func TestBootstrapCommandsRefuseARelativeLayoutBeforeAnythingElse(t *testing.T) {
	pretendRoot(t, true)
	for name, run := range map[string]func(context.Context, *bytes.Buffer, []string) error{
		"apply": func(ctx context.Context, out *bytes.Buffer, a []string) error { return runBootstrapApply(ctx, out, a) },
		"rollback": func(ctx context.Context, out *bytes.Buffer, a []string) error {
			return runBootstrapRollback(ctx, out, a)
		},
		"rotate": func(ctx context.Context, out *bytes.Buffer, a []string) error {
			return runBootstrapRotate(ctx, out, append(a, "-users", "owner"))
		},
	} {
		err := run(context.Background(), &bytes.Buffer{}, []string{"-yes", "-config-root", "relative"})
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRollbackNeedsSomethingEarlierToRollBackTo(t *testing.T) {
	pretendRoot(t, true)
	ownTransactions(t)
	layout := freshLayout(t)

	if _, _, err := synthesizeRollback(layout, 0); err == nil || !strings.Contains(err.Error(), "no committed generation") {
		t.Errorf("empty history: %v", err)
	}
	commitDesired(t, layout, state.Default([]string{"owner"}))
	if _, _, err := synthesizeRollback(layout, 0); err == nil || !strings.Contains(err.Error(), "no earlier committed generation") {
		t.Errorf("a single generation: %v", err)
	}
	commitDesired(t, layout, state.Default([]string{"owner"}))
	if _, _, err := synthesizeRollback(layout, 99); err == nil {
		t.Error("a generation that does not exist was selected")
	}
	// The stored intent being unreadable stops the rollback rather than guessing.
	if err := os.WriteFile(layout.DesiredPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := synthesizeRollback(layout, 0); err == nil || !strings.Contains(err.Error(), "read current desired state") {
		t.Errorf("corrupt intent: %v", err)
	}
}
