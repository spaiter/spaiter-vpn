package external

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func fastPoll(t *testing.T) {
	t.Helper()
	oldPoll, oldTimeout := WARPPollInterval, WARPRegisterTimeout
	WARPPollInterval, WARPRegisterTimeout = 5*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { WARPPollInterval, WARPRegisterTimeout = oldPoll, oldTimeout })
}

func TestConstructorsFallBackToTheDefaultLogger(t *testing.T) {
	if NewHashChecker("x", nil).log == nil || NewWARPRegistrar("x", nil, nil).log == nil {
		t.Error("no default logger")
	}
}

func TestEmptyBinaryNamesAreRefusedBeforeAnythingRuns(t *testing.T) {
	if _, err := NewHashChecker("", quiet()).Check(context.Background(), []string{"h"}); err == nil || !strings.Contains(err.Error(), "no hash-check binary") {
		t.Errorf("hash checker: %v", err)
	}
	if _, err := NewWARPRegistrar("", nil, quiet()).Register(context.Background()); err == nil || !strings.Contains(err.Error(), "no WARP binary") {
		t.Errorf("registrar: %v", err)
	}
}

func TestMalformedVerdictLinesAreSkipped(t *testing.T) {
	got := parseHashCheck([]byte("noise\nHASH_CHECK|\nHASH_CHECK||ok\nHASH_CHECK|only\nHASH_CHECK|good|ok\n"))
	if len(got) != 1 || got["good"].Status != "ok" {
		t.Errorf("verdicts = %v", got)
	}
	if firstLine("one\ntwo") != "one" || firstLine("single") != "single" {
		t.Error("firstLine")
	}
}

func TestRegistrationFailuresAreNamed(t *testing.T) {
	fastPoll(t)

	// A configuration that cannot be rendered.
	bin := fakeBinary(t, `sleep 1`)
	r := NewWARPRegistrar(bin, func(string) any { return make(chan int) }, quiet())
	if _, err := r.Register(context.Background()); err == nil || !strings.Contains(err.Error(), "render registration config") {
		t.Errorf("unrenderable config: %v", err)
	}

	// A binary that exists but cannot be started.
	notExecutable := fakeBinary(t, `true`)
	if err := os.Chmod(notExecutable, 0o644); err != nil {
		t.Fatal(err)
	}
	r = NewWARPRegistrar(notExecutable, func(string) any { return map[string]any{} }, quiet())
	if _, err := r.Register(context.Background()); err == nil || !strings.Contains(err.Error(), "start") {
		t.Errorf("unstartable binary: %v", err)
	}

	// The helper writes a database with no account, then a half-written one,
	// and never a finished one: polling skips both and gives up.
	partial := fakeBinary(t, `
cfg=""
while [ $# -gt 0 ]; do [ "$1" = "-c" ] && cfg="$2"; shift; done
db=$(grep -o '"path": *"[^"]*"' "$cfg" | head -1 | sed 's/.*"\(\/[^"]*\)"/\1/')
printf 'no json here' > "$db"
sleep 0.1
printf '{"private_key":"","ipv4":"1.2.3.4"}' > "$db"
while true; do sleep 1; done
`)
	r = NewWARPRegistrar(partial, func(cacheDB string) any {
		return map[string]any{"path": cacheDB}
	}, quiet())
	if _, err := r.Register(context.Background()); err == nil || !strings.Contains(err.Error(), "produced no account") {
		t.Errorf("partial records: %v", err)
	}
}
