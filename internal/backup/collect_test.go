package backup

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func putFile(t *testing.T, p string, mode os.FileMode, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func names(s *Snapshot) []string {
	var out []string
	for _, f := range s.Files {
		out = append(out, string(f.Root)+"/"+f.Path)
	}
	slices.Sort(out)
	return out
}

func TestAddReadsRegularFilesAndIgnoresTheRest(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "secret")
	putFile(t, regular, 0o640, "hunter2")
	if err := os.Symlink(regular, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := &Snapshot{}
	if err := s.Add(RootConfig, "credentials/secret", regular); err != nil {
		t.Fatal(err)
	}
	// A missing file is normal (the feature is off); a symlink or directory is
	// not something to follow into the archive.
	for _, source := range []string{filepath.Join(dir, "absent"), filepath.Join(dir, "link"), filepath.Join(dir, "subdir")} {
		if err := s.Add(RootConfig, "x/"+filepath.Base(source), source); err != nil {
			t.Fatalf("%s: %v", source, err)
		}
	}
	if got := names(s); len(got) != 1 || got[0] != "config/credentials/secret" {
		t.Fatalf("snapshot holds %v, want only the regular file", got)
	}
	f := s.Files[0]
	if f.Mode != 0o640 || f.Size != 7 || string(f.Data) != "hunter2" {
		t.Fatalf("entry = %+v", f.Entry)
	}
	// SHA-256 of "hunter2".
	if f.SHA256 != "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7" {
		t.Fatalf("sha256 = %s", f.SHA256)
	}
}

func TestAddDataRefusesUnsafePathsAndDuplicates(t *testing.T) {
	s := &Snapshot{}
	for _, rel := range []string{"", ".", "..", "../etc/passwd", "/etc/passwd", "a/../b", "a//b", `a\b`, "a/./b"} {
		if err := s.AddData(RootConfig, rel, 0o600, []byte("x")); err == nil {
			t.Errorf("path %q was accepted", rel)
		}
	}
	if len(s.Files) != 0 {
		t.Fatalf("unsafe paths left entries behind: %v", names(s))
	}
	if err := s.AddData(RootConfig, "a", 0o600, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddData(RootData, "a", 0o600, []byte("2")); err != nil {
		t.Fatalf("the same name under another root is a different file: %v", err)
	}
	err := s.AddData(RootConfig, "a", 0o600, []byte("3"))
	if err == nil || !strings.Contains(err.Error(), "added twice") {
		t.Fatalf("duplicate was not refused: %v", err)
	}
}

func TestAddTreeWalksNestedFilesHonoursSkipAndPrefix(t *testing.T) {
	dir := t.TempDir()
	putFile(t, filepath.Join(dir, "top.json"), 0o600, "1")
	putFile(t, filepath.Join(dir, "deep/er/leaf.json"), 0o600, "2")
	putFile(t, filepath.Join(dir, ".reload-core"), 0o600, "marker")
	if err := os.Symlink(filepath.Join(dir, "top.json"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}

	s := &Snapshot{}
	err := s.AddTree(RootData, "bot", dir, func(rel string) bool { return strings.HasPrefix(rel, ".reload-") })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"data/bot/deep/er/leaf.json", "data/bot/top.json"}
	if got := names(s); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAddTreeOfAMissingDirectoryIsEmptyNotAnError(t *testing.T) {
	s := &Snapshot{}
	if err := s.AddTree(RootData, "cache", filepath.Join(t.TempDir(), "never-created"), nil); err != nil {
		t.Fatal(err)
	}
	if len(s.Files) != 0 {
		t.Fatalf("unexpected entries %v", names(s))
	}
}

func TestAddTreeWithDotPrefixKeepsRelativeNames(t *testing.T) {
	dir := t.TempDir()
	putFile(t, filepath.Join(dir, "passwords.json"), 0o640, "{}")
	s := &Snapshot{}
	if err := s.AddTree(RootRelay, ".", dir, nil); err != nil {
		t.Fatal(err)
	}
	if got := names(s); !slices.Equal(got, []string{"relay/passwords.json"}) {
		t.Fatalf("got %v", got)
	}
}

func TestIsDatabaseSidecar(t *testing.T) {
	for rel, want := range map[string]bool{
		"cache.db-wal": true, "cache.db-shm": true, "cache.db-journal": true,
		"cache.db": false, "certmagic/acme/account.json": false, "wal": false,
	} {
		if got := isDatabaseSidecar(rel); got != want {
			t.Errorf("isDatabaseSidecar(%q) = %v, want %v", rel, got, want)
		}
	}
}

// makeDeployment lays out a bootstrap-managed host under a temp root.
func makeDeployment(t *testing.T) (discover.Layout, string) {
	t.Helper()
	root := t.TempDir()
	layout := discover.Layout{ConfigRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "var")}
	relay := filepath.Join(root, "relay")

	desired := state.Default([]string{"alice"})
	desired.Bot.PublicHost = "203.0.113.7"
	desired.Bot.WDTTConfigDirectory = relay
	raw, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	putFile(t, layout.DesiredPath(), 0o600, string(raw))
	putFile(t, layout.ConfigPath(), 0o600, `{"inbounds":[]}`)
	putFile(t, layout.SecretsPath(), 0o600, `{"users":[]}`)
	putFile(t, filepath.Join(layout.CredentialDir(), "telegram-token"), 0o600, "123:abc")
	putFile(t, filepath.Join(layout.BotDataDir(), "wdtt", "subs.json"), 0o600, `{"tok":{}}`)
	putFile(t, filepath.Join(layout.BotDataDir(), ".reload-core"), 0o600, "marker")
	putFile(t, filepath.Join(layout.CacheDir(), "certmagic", "acme", "account.json"), 0o600, `{}`)
	putFile(t, filepath.Join(layout.CacheDir(), "cache.db"), 0o600, "runtime cache")
	putFile(t, filepath.Join(layout.CacheDir(), "cache.db-wal"), 0o600, "wal")
	putFile(t, filepath.Join(relay, "passwords.json"), 0o640, `{}`)
	return layout, relay
}

func seedStatsDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE traffic (user TEXT PRIMARY KEY, bytes INTEGER)`,
		`INSERT INTO traffic VALUES ('alice', 1234567)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCollectGathersStateAndLeavesRuntimeNoiseBehind(t *testing.T) {
	layout, _ := makeDeployment(t)
	seedStatsDB(t, filepath.Join(layout.DeploymentDir(), "user_stats.db"))

	snap, err := Collect(layout, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Manifest.Version != "1.2.3" || snap.Manifest.PublicHost != "203.0.113.7" {
		t.Fatalf("manifest = %+v", snap.Manifest)
	}
	if snap.Manifest.Created.IsZero() || snap.Manifest.Created.Location().String() != "UTC" {
		t.Fatalf("created = %v, want a UTC timestamp", snap.Manifest.Created)
	}
	want := []string{
		"config/credentials/telegram-token",
		"config/deployment/config.json",
		"config/deployment/secrets/secrets.json",
		"config/deployment/user_stats.db",
		"config/desired.json",
		"data/bot/wdtt/subs.json",
		"data/cache/certmagic/acme/account.json",
		"relay/passwords.json",
	}
	if got := names(snap); !slices.Equal(got, want) {
		t.Fatalf("collected\n  %v\nwant\n  %v", got, want)
	}

	// The statistics database travels as a consistent copy that still opens.
	stats, ok := snap.Lookup(RootConfig, StatsPath)
	if !ok {
		t.Fatal("no stats entry")
	}
	copyPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(copyPath, stats.Data, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var bytes int64
	if err := db.QueryRow(`SELECT bytes FROM traffic WHERE user = 'alice'`).Scan(&bytes); err != nil || bytes != 1234567 {
		t.Fatalf("copy of the stats database: bytes=%d err=%v", bytes, err)
	}
}

func TestCollectWithoutOptionalPartsStillSucceeds(t *testing.T) {
	layout, relay := makeDeployment(t)
	// No traffic database yet, no cache, no relay directory on disk.
	for _, p := range []string{layout.CacheDir(), relay} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := Collect(layout, "dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names(snap) {
		if strings.Contains(n, "user_stats") || strings.HasPrefix(n, "relay/") || strings.HasPrefix(n, "data/cache/") {
			t.Errorf("%s was collected from something that does not exist", n)
		}
	}
}

func TestCollectNamesTheProblemOnAHostBootstrapDoesNotManage(t *testing.T) {
	layout := discover.Layout{ConfigRoot: filepath.Join(t.TempDir(), "etc"), DataRoot: t.TempDir()}
	_, err := Collect(layout, "dev")
	if err == nil || !strings.Contains(err.Error(), "bootstrap-managed") {
		t.Fatalf("no desired state: %v", err)
	}

	layout, _ = makeDeployment(t)
	if err := os.Remove(layout.ConfigPath()); err != nil {
		t.Fatal(err)
	}
	_, err = Collect(layout, "dev")
	if err == nil || !strings.Contains(err.Error(), "config.json") {
		t.Fatalf("a missing config must fail and say which file: %v", err)
	}
}

func TestAddDatabaseRefusesAFileThatIsNotSQLite(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "user_stats.db")
	putFile(t, bogus, 0o600, "this is not a database, just bytes that merely sit where one should be")
	s := &Snapshot{}
	err := addDatabase(s, RootConfig, StatsPath, bogus)
	if err == nil {
		t.Fatal("a corrupt database was archived as if it were good")
	}
	if len(s.Files) != 0 {
		t.Fatalf("a failed copy left an entry: %v", names(s))
	}
}

func TestAddDatabaseOfAMissingFileIsNotAnError(t *testing.T) {
	s := &Snapshot{}
	if err := addDatabase(s, RootConfig, StatsPath, filepath.Join(t.TempDir(), "absent.db")); err != nil {
		t.Fatal(err)
	}
	if len(s.Files) != 0 {
		t.Fatalf("unexpected entries %v", names(s))
	}
}
