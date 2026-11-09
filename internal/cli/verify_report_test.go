package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/verify"
)

func runVerifyWith(t *testing.T, results []verify.Result, args ...string) (string, error, string, string) {
	t.Helper()
	var gotTarget string
	var gotTimeout time.Duration
	old := verifyRun
	t.Cleanup(func() { verifyRun = old })
	verifyRun = func(_ context.Context, _ []byte, _ verify.Runner, target string, timeout time.Duration) ([]verify.Result, error) {
		gotTarget, gotTimeout = target, timeout
		return results, nil
	}
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(bundle, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runVerify(context.Background(), &out, append([]string{"-bundle", bundle}, args...))
	return out.String(), err, gotTarget, gotTimeout.String()
}

func TestVerifyPrintsOneLinePerNodeAndPassesWhenNoneFailed(t *testing.T) {
	out, err, target, timeout := runVerifyWith(t, []verify.Result{
		{Node: "VLESS Reality", Type: "vless", Delay: 42 * time.Millisecond},
		{Node: "WG-over-VK", Type: "wdtt", Skipped: "needs a call"},
	}, "-url", "https://example.com/x", "-timeout", "3s", "-sing-box", "/opt/core")
	if err != nil {
		t.Fatalf("err = %v\n%s", err, out)
	}
	for _, want := range []string{"PASS  VLESS Reality", "42ms", "SKIP  WG-over-VK", "needs a call", "every node this core can run passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if target != "https://example.com/x" || timeout != "3s" {
		t.Errorf("target=%q timeout=%q were not passed through", target, timeout)
	}
}

func TestVerifyFailsWhenAnyNodeFails(t *testing.T) {
	out, err, _, _ := runVerifyWith(t, []verify.Result{
		{Node: "A", Type: "vless", Delay: time.Millisecond},
		{Node: "TUIC", Type: "tuic", Error: "i/o timeout"},
	})
	if err == nil || !strings.Contains(err.Error(), "1 of 2 nodes failed") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out, "FAIL  TUIC") || !strings.Contains(out, "i/o timeout") || strings.Contains(out, "every node") {
		t.Errorf("output:\n%s", out)
	}
}
