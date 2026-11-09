package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func statusLayout(t *testing.T) (discover.Layout, []string) {
	t.Helper()
	root := t.TempDir()
	layout := discover.DefaultLayout()
	layout.ConfigRoot, layout.DataRoot = filepath.Join(root, "etc"), filepath.Join(root, "var")
	return layout, []string{"-config-root", layout.ConfigRoot, "-data-root", layout.DataRoot}
}

// dockerPrinting puts a `docker` on PATH whose compose ps prints the given JSON.
func dockerPrinting(t *testing.T, psJSON string) {
	t.Helper()
	dir := t.TempDir()
	body := "#!/bin/sh\ncase \"$1\" in version) exit 0;; esac\nprintf '%s\\n' '" + psJSON + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestStatusReportsIntentPackagesAndServices(t *testing.T) {
	layout, args := statusLayout(t)
	writeDesired(t, layout, state.Default([]string{"owner", "guest"}))
	if err := os.MkdirAll(filepath.Dir(layout.PlatformRecordPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	record := dockerinstall.Record{
		InstalledAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Release: "ubuntu 24.04",
		Packages: map[string]string{"docker-ce": "5:29.0", "containerd.io": "1.7"},
		Files:    []string{"/etc/apt/keyrings/docker.asc"},
	}
	if err := dockerinstall.WriteRecord(layout.PlatformRecordPath(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ComposePath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ComposePath(), []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dockerPrinting(t, `[{"Service":"core","State":"running"},{"Service":"bot","State":"restarting","Health":"unhealthy"},{"Service":"once","State":"exited"}]`)

	var out bytes.Buffer
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"stored intent:", "users:   2 seeded", "host packages: installed by bootstrap on 2026-11-01 (ubuntu 24.04)",
		"containerd.io=1.7", "docker-ce=5:29.0", "/etc/apt/keyrings/docker.asc",
		"core", "running", "restarting/unhealthy", "exited",
		"management:    not answered", // no core config in the layout
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	// Packages are listed in name order.
	if strings.Index(text, "containerd.io") > strings.Index(text, "docker-ce=") {
		t.Errorf("packages are not sorted:\n%s", text)
	}
}

func TestStatusWithoutProbeOrWithNoRunningProject(t *testing.T) {
	layout, args := statusLayout(t)
	os.MkdirAll(filepath.Dir(layout.ComposePath()), 0o755)
	os.WriteFile(layout.ComposePath(), []byte("services: {}\n"), 0o600)
	dockerPrinting(t, ``)
	var out bytes.Buffer
	if err := runBootstrapStatus(context.Background(), &out, append(args, "-probe=false")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "none; the project is not running") || strings.Contains(out.String(), "management:") {
		t.Errorf("output:\n%s", out.String())
	}

	// Docker that cannot be found is reported, not fatal.
	t.Setenv("PATH", t.TempDir())
	out.Reset()
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "cannot be read") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestStatusSaysWhenTheComposeProjectIsAbsentOrDockerBreaks(t *testing.T) {
	layout, args := statusLayout(t)
	var out bytes.Buffer
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil || !strings.Contains(out.String(), "no compose project at") {
		t.Fatalf("err=%v\n%s", err, out.String())
	}
	os.MkdirAll(filepath.Dir(layout.ComposePath()), 0o755)
	os.WriteFile(layout.ComposePath(), []byte("services: {}\n"), 0o600)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\ncase \"$1\" in version) exit 0;; esac\necho nope >&2\nexit 1\n"), 0o755)
	t.Setenv("PATH", dir)
	out.Reset()
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil || !strings.Contains(out.String(), "cannot be read") {
		t.Fatalf("err=%v\n%s", err, out.String())
	}
}

func TestStatusReportsAnUnreadablePackageRecord(t *testing.T) {
	layout, args := statusLayout(t)
	os.MkdirAll(filepath.Dir(layout.PlatformRecordPath()), 0o755)
	os.WriteFile(layout.PlatformRecordPath(), []byte("{broken"), 0o600)
	var out bytes.Buffer
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "host packages: UNREADABLE record") {
		t.Errorf("output:\n%s", out.String())
	}
}
