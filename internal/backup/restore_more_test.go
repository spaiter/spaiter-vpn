package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestDeploymentReturnsWhatBootstrapRendersTheNewHostFrom(t *testing.T) {
	desired := state.Default([]string{"owner"})
	raw, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	s := &Snapshot{}
	for rel, data := range map[string]string{DesiredPath: string(raw), ConfigPath: `{"inbounds":[]}`, SecretsPath: `{"s":1}`} {
		if err := s.AddData(RootConfig, rel, 0o600, []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	got, config, secrets, err := s.Deployment()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Bootstrap.SeedUsers) != 1 || string(config) != `{"inbounds":[]}` || string(secrets) != `{"s":1}` {
		t.Errorf("state=%+v config=%q secrets=%q", got.Bootstrap, config, secrets)
	}

	// Each of the three is required, and the state must parse.
	for _, missing := range []string{DesiredPath, ConfigPath, SecretsPath} {
		partial := &Snapshot{}
		for _, f := range s.Files {
			if f.Path != missing {
				partial.Files = append(partial.Files, f)
			}
		}
		if _, _, _, err := partial.Deployment(); err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("without %s: %v", missing, err)
		}
	}
	bad := &Snapshot{}
	for rel, data := range map[string]string{DesiredPath: "{broken", ConfigPath: "{}", SecretsPath: "{}"} {
		bad.AddData(RootConfig, rel, 0o600, []byte(data))
	}
	if _, _, _, err := bad.Deployment(); err == nil || !strings.Contains(err.Error(), "parse the archived desired state") {
		t.Errorf("unparsable state: %v", err)
	}
}

func TestTargetRefusesWhatWouldLeaveItsRoot(t *testing.T) {
	layout := discover.Layout{ConfigRoot: "/etc/x", DataRoot: "/var/x"}
	if _, err := target(layout, "", File{Entry: Entry{Root: RootRelay, Path: "p.json"}}); err == nil || !strings.Contains(err.Error(), "no relay directory") {
		t.Errorf("relay without a directory: %v", err)
	}
	if _, err := target(layout, "", File{Entry: Entry{Root: Root("weird"), Path: "p"}}); err == nil {
		t.Error("an unknown root was resolved")
	}
	if _, err := target(layout, "", File{Entry: Entry{Root: RootData, Path: "../escape"}}); err == nil {
		t.Error("a path outside its root was resolved")
	}
	if got, err := target(layout, "", File{Entry: Entry{Root: RootData, Path: "bot/a.json"}}); err != nil || got != "/var/x/bot/a.json" {
		t.Errorf("= %q, %v", got, err)
	}
	if got, _ := target(layout, "/relay", File{Entry: Entry{Root: RootRelay, Path: "p.json"}}); got != "/relay/p.json" {
		t.Errorf("relay = %q", got)
	}
}

func TestPlaceAndCheckFreshReportUnwritableAndInvalidArchives(t *testing.T) {
	root := t.TempDir()
	layout := discover.Layout{ConfigRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "var")}

	// A snapshot that names a relay file but no relay directory fails before writing.
	s := &Snapshot{}
	s.AddData(RootRelay, "p.json", 0o600, []byte("{}"))
	if err := CheckFresh(s, layout, ""); err == nil {
		t.Error("CheckFresh accepted a relay file with nowhere to go")
	}
	if written, err := Place(s, layout, ""); err == nil || len(written) != 0 {
		t.Errorf("Place = %v, %v", written, err)
	}

	// A data file whose parent is a regular file cannot be created.
	blocker := filepath.Join(root, "var")
	os.WriteFile(blocker, []byte("file"), 0o600)
	s2 := &Snapshot{}
	s2.AddData(RootData, "bot/a.json", 0o600, []byte("{}"))
	if _, err := Place(s2, layout, ""); err == nil {
		t.Error("a file under a regular file was placed")
	}

	// A receipt already present means a deployment is there.
	os.Remove(blocker)
	os.MkdirAll(filepath.Dir(layout.CurrentReceiptPath()), 0o700)
	os.WriteFile(layout.CurrentReceiptPath(), []byte("{}"), 0o600)
	if err := CheckFresh(&Snapshot{}, layout, ""); !errors.Is(err, ErrNotFresh) {
		t.Errorf("a receipt did not count as a deployment: %v", err)
	}
}

func TestLookupFindsFilesByRootAndPath(t *testing.T) {
	s := &Snapshot{}
	s.AddData(RootConfig, "a", 0o600, []byte("1"))
	s.AddData(RootData, "a", 0o600, []byte("2"))
	if f, ok := s.Lookup(RootData, "a"); !ok || string(f.Data) != "2" {
		t.Errorf("= %v %v", f, ok)
	}
	if _, ok := s.Lookup(RootRelay, "a"); ok {
		t.Error("found a file under the wrong root")
	}
}
