package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestInitPreflightCanBeSkippedAndSaysSo(t *testing.T) {
	var out bytes.Buffer
	if err := runPreflightForInit(context.Background(), &out, initFlags{skipPreflight: true}, profile.Defaults([]string{"alice"}), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("a skipped preflight printed on stdout: %q", out.String())
	}
}

// The checks depend on the machine running the test, so this holds the shape of
// the answer rather than its verdict: a failure always names the way out, and a
// pass always reports something.
func TestInitPreflightEitherFailsWithTheWayOutOrReports(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = nil
	for _, strict := range []bool{false, true} {
		var out bytes.Buffer
		flags := initFlags{strict: strict, out: t.TempDir(), singBoxBinary: "sh"}
		err := runPreflightForInit(context.Background(), &out, flags, spec, t.TempDir())
		switch {
		case err != nil && !strings.Contains(err.Error(), "-skip-preflight"):
			t.Errorf("strict=%v: a failure without the way out: %v", strict, err)
		case err == nil && out.Len() == 0:
			t.Errorf("strict=%v: a pass reported nothing", strict)
		}
	}
}

func TestLogsExplainThemselvesOnHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runLogs(context.Background(), &out, []string{"-h"}); err == nil || !strings.Contains(err.Error(), "help requested") {
		t.Errorf("-h: %v", err)
	}
	if !strings.Contains(out.String(), "usage: spaiter-vpn logs") {
		t.Errorf("usage:\n%s", out.String())
	}
}
