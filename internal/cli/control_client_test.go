package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/control"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// recordingBackend answers the control socket with canned results and
// remembers what it was asked to plan.
type recordingBackend struct {
	prepared  []control.Change
	committed int
}

func (b *recordingBackend) Status(context.Context) (any, error) {
	return map[string]string{"tier": "a"}, nil
}
func (b *recordingBackend) Generations(context.Context) (any, error) { return []int{1, 2}, nil }
func (b *recordingBackend) Preflight(_ context.Context, out io.Writer) (any, error) {
	io.WriteString(out, "preflight line without a newline")
	return nil, nil
}
func (b *recordingBackend) SelfTest(context.Context, io.Writer) error {
	return errors.New("selftest failed loudly")
}
func (b *recordingBackend) Redact(text string) string { return text }
func (b *recordingBackend) Prepare(_ context.Context, change control.Change, _ io.Writer) (control.Prepared, error) {
	b.prepared = append(b.prepared, change)
	return control.Prepared{Plan: "the plan", Commit: func(context.Context, io.Writer) (any, string, error) {
		b.committed++
		return map[string]bool{"done": true}, "tx-1", nil
	}}, nil
}

func startControl(t *testing.T) (string, *recordingBackend) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	backend := &recordingBackend{}
	server := &control.Server{
		Socket:  filepath.Join(dir, "c.sock"),
		Access:  control.Access{APIVersion: control.APIVersion, Operators: []uint32{uint32(os.Getuid())}},
		Backend: backend,
		Audit:   &control.Audit{Path: filepath.Join(dir, "audit.log")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(server.Socket); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return server.Socket, backend
}

func runCtl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runControl(context.Background(), &out, args)
	return out.String(), err
}

func TestControlClientSubcommandsTalkToTheDaemon(t *testing.T) {
	socket, backend := startControl(t)

	out, err := runCtl(t, "status", "-socket", socket)
	if err != nil || !strings.Contains(out, `"tier": "a"`) {
		t.Errorf("status: %q %v", out, err)
	}
	if out, err = runCtl(t, "generations", "-socket", socket); err != nil || !strings.Contains(out, "2") {
		t.Errorf("generations: %q %v", out, err)
	}
	// Output without a trailing newline gets one, so the next line is not glued to it.
	if out, err = runCtl(t, "preflight", "-socket", socket); err != nil || !strings.HasPrefix(out, "preflight line without a newline\n") {
		t.Errorf("preflight: %q %v", out, err)
	}
	// A daemon-side failure is the command's failure, with the daemon's words.
	if _, err = runCtl(t, "selftest", "-socket", socket); err == nil || !strings.Contains(err.Error(), "selftest failed loudly") {
		t.Errorf("selftest: %v", err)
	}

	out, err = runCtl(t, "prepare", "-socket", socket, "-port", "awg-in=23456", "-mtu", "awg-in=1280", "-enable", "mieru-in", "-disable", "snell-in")
	if err != nil || len(backend.prepared) != 1 {
		t.Fatalf("prepare: %q %v", out, err)
	}
	got := backend.prepared[0]
	if got.Kind != control.ChangeSettings || got.Ports["awg-in"] != 23456 || got.MTU["awg-in"] != 1280 ||
		len(got.Enable) != 1 || len(got.Disable) != 1 {
		t.Errorf("change = %+v", got)
	}
	id := ticketID(t, out)

	if _, err = runCtl(t, "commit", "-socket", socket, id); err != nil || backend.committed != 1 {
		t.Errorf("commit: %v (commits %d)", err, backend.committed)
	}
	// A spent ticket cannot be replayed.
	if _, err = runCtl(t, "commit", "-socket", socket, id); err == nil || backend.committed != 1 {
		t.Errorf("replayed commit: %v (commits %d)", err, backend.committed)
	}

	out, _ = runCtl(t, "prepare", "-socket", socket, "-rollback", "-generation", "3")
	if c := backend.prepared[len(backend.prepared)-1]; c.Kind != control.ChangeRollback || c.Generation != 3 {
		t.Errorf("rollback change = %+v", c)
	}
	if _, err = runCtl(t, "cancel", "-socket", socket, ticketID(t, out)); err != nil {
		t.Errorf("cancel: %v", err)
	}
	runCtl(t, "prepare", "-socket", socket, "-image", "repo/core:next")
	if c := backend.prepared[len(backend.prepared)-1]; c.Kind != control.ChangeImage || c.Image != "repo/core:next" {
		t.Errorf("image change = %+v", c)
	}
	runCtl(t, "prepare", "-socket", socket, "-rotate", "alice,bob")
	if c := backend.prepared[len(backend.prepared)-1]; c.Kind != control.ChangeRotate || len(c.Users) != 2 {
		t.Errorf("rotate change = %+v", c)
	}
}

func ticketID(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, `"id": "`)
	if i < 0 {
		t.Fatalf("no ticket in %q", out)
	}
	rest := out[i+len(`"id": "`):]
	return rest[:strings.IndexByte(rest, '"')]
}

func TestControlRefusesBadInputBeforeAskingTheDaemon(t *testing.T) {
	socket, backend := startControl(t)
	for name, args := range map[string][]string{
		"no subcommand":       {},
		"unknown subcommand":  {"explode"},
		"port without equals": {"prepare", "-socket", socket, "-port", "awg-in"},
		"port not a number":   {"prepare", "-socket", socket, "-port", "awg-in=http"},
		"port too large":      {"prepare", "-socket", socket, "-port", "awg-in=70000"},
		"mtu not a number":    {"prepare", "-socket", socket, "-mtu", "awg-in=x"},
		"empty settings":      {"prepare", "-socket", socket},
		"commit without id":   {"commit", "-socket", socket},
		"cancel with two":     {"cancel", "-socket", socket, "a", "b"},
	} {
		_, err := runCtl(t, args...)
		if !errors.Is(err, ErrUsage) {
			t.Errorf("%s: %v, want ErrUsage", name, err)
		}
	}
	if len(backend.prepared) != 0 {
		t.Errorf("the daemon was asked to plan %d malformed changes", len(backend.prepared))
	}
	// A dead socket is an error, not a hang or a silent success.
	if _, err := runCtl(t, "status", "-socket", filepath.Join(t.TempDir(), "none.sock")); err == nil {
		t.Error("an absent daemon reported success")
	}
}

func TestControlHelpAndUnit(t *testing.T) {
	out, err := runCtl(t, "-h")
	if err != nil || !strings.Contains(out, "prepare") || !strings.Contains(out, "commit ID") {
		t.Errorf("help: %q %v", out, err)
	}
	if _, err := runCtl(t); !errors.Is(err, ErrUsage) {
		t.Errorf("bare control must exit as a usage error: %v", err)
	}
	out, err = runCtl(t, "unit")
	if err != nil || !strings.Contains(out, "control serve") || !strings.Contains(out, "[Service]") {
		t.Errorf("unit: %q %v", out, err)
	}
}

func TestControlServeRefusesWithoutRootAndWithPositionalArguments(t *testing.T) {
	if _, err := runCtl(t, "serve", "extra"); !errors.Is(err, ErrUsage) {
		t.Errorf("positional: %v", err)
	}
	if _, err := runCtl(t, "serve", "-config-root", "relative"); !errors.Is(err, ErrUsage) {
		t.Errorf("relative layout: %v", err)
	}
	if os.Geteuid() != 0 {
		if _, err := runCtl(t, "serve"); err == nil || !strings.Contains(err.Error(), "as root") {
			t.Errorf("unprivileged serve: %v", err)
		}
	}
}

func TestControlDesiredEditsAreRevalidatedAndExact(t *testing.T) {
	current := state.Default([]string{"owner"})
	now := time.Now()

	// Disable then enable round-trips, and the disabled list is sorted and unique.
	d, err := controlDesired(current, control.Change{Kind: control.ChangeSettings, Disable: []string{"snell-in", "mieru-in", "snell-in"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	dis := d.Deployment.Protocols.Disabled
	if len(dis) != 2 || dis[0] > dis[1] {
		t.Errorf("disabled = %v", dis)
	}
	back, err := controlDesired(d, control.Change{Kind: control.ChangeSettings, Enable: []string{"snell-in", "mieru-in"}}, now)
	if err != nil || len(back.Deployment.Protocols.Disabled) != 0 {
		t.Errorf("re-enable: %v %v", back.Deployment.Protocols.Disabled, err)
	}
	if len(current.Deployment.Protocols.Disabled) != 0 {
		t.Error("the current state was mutated through a shared slice")
	}

	for name, change := range map[string]control.Change{
		"unknown mtu":     {Kind: control.ChangeSettings, MTU: map[string]uint32{"ssh": 1280}},
		"unknown enable":  {Kind: control.ChangeSettings, Enable: []string{"ssh"}},
		"unknown disable": {Kind: control.ChangeSettings, Disable: []string{"ssh"}},
		"rollback here":   {Kind: control.ChangeRollback},
		"no kind":         {},
	} {
		if _, err := controlDesired(current, change, now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A port clash is caught by the revalidation, not by the daemon's luck.
	taken := current.Deployment.Ports[profile.AWG2]
	if _, err := controlDesired(current, control.Change{Kind: control.ChangeSettings, Ports: map[string]uint16{"awg3-in": taken}}, now); err == nil {
		t.Error("two protocols on one port were accepted")
	}
}

func TestControlRedactScrubsTheManagementSecret(t *testing.T) {
	dir := t.TempDir()
	layout := discover.Layout{ConfigRoot: dir + "/etc", DataRoot: dir + "/var"}
	b := &controlBackend{layout: layout}
	if got := b.Redact("nothing to hide"); got != "nothing to hide" {
		t.Errorf("without a config: %q", got)
	}
	os.MkdirAll(filepath.Dir(layout.ConfigPath()), 0o755)
	cfg := `{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090","secret":"management-secret-value"}}}`
	os.WriteFile(layout.ConfigPath(), []byte(cfg), 0o600)
	if got := b.Redact("error talking to management-secret-value at 127.0.0.1"); strings.Contains(got, "management-secret-value") || !strings.Contains(got, "[redacted]") {
		t.Errorf("secret leaked to the caller: %q", got)
	}
	os.WriteFile(layout.ConfigPath(), []byte("{broken"), 0o600)
	if got := b.Redact("plain"); got != "plain" {
		t.Errorf("a broken config: %q", got)
	}
}
