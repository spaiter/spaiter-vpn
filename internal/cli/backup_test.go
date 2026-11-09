package cli

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/spaiter/spaiter-vpn/internal/backup"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func asRoot(t *testing.T) {
	t.Helper()
	old := runningAsRoot
	runningAsRoot = func() bool { return true }
	t.Cleanup(func() { runningAsRoot = old })
}

// deployedLayout lays out what a bootstrap install leaves on disk, small.
func deployedLayout(t *testing.T) discover.Layout {
	t.Helper()
	onHost(t, nil, nil)
	root := t.TempDir()
	layout := discover.Layout{ConfigRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "var")}
	os.MkdirAll(filepath.Dir(layout.SecretsPath()), 0o700)
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, []string{"-users", "alice", "-o", layout.DesiredPath(), "-public-host", "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		layout.ConfigPath():  `{"inbounds":[]}`,
		layout.SecretsPath(): `{}`,
		filepath.Join(layout.CredentialDir(), "telegram-token"):    "123:abc",
		filepath.Join(layout.BotDataDir(), "wdtt", "subs.json"):    `{"tok":{"uid":"1"}}`,
		filepath.Join(layout.BotDataDir(), ".reload-singbox"):      "",
		filepath.Join(layout.CacheDir(), "cache.db"):               "runtime",
		filepath.Join(layout.CacheDir(), "certmagic", "acct.json"): `{}`,
	} {
		os.MkdirAll(filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(layout.DeploymentDir(), "user_stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE user_stats_daily (user TEXT, download INTEGER); INSERT INTO user_stats_daily VALUES ('alice', 42)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return layout
}

func TestBackupCollectsTheDeploymentEncrypted(t *testing.T) {
	asRoot(t)
	layout := deployedLayout(t)
	passFile := filepath.Join(t.TempDir(), "pass")
	os.WriteFile(passFile, []byte("a long enough passphrase\n"), 0o600)

	var archive bytes.Buffer
	args := []string{"-config-root", layout.ConfigRoot, "-data-root", layout.DataRoot, "-passphrase-file", passFile}
	if err := runBackup(context.Background(), &archive, args); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive.Bytes(), []byte("123:abc")) {
		t.Fatal("the archive is not encrypted")
	}
	identity, _ := age.NewScryptIdentity("a long enough passphrase")
	snap, err := backup.Read(bytes.NewReader(archive.Bytes()), identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		root backup.Root
		rel  string
	}{
		{backup.RootConfig, backup.DesiredPath},
		{backup.RootConfig, backup.ConfigPath},
		{backup.RootConfig, "credentials/telegram-token"},
		{backup.RootConfig, backup.StatsPath},
		{backup.RootData, "bot/wdtt/subs.json"},
		{backup.RootData, "cache/certmagic/acct.json"},
	} {
		if _, ok := snap.Lookup(want.root, want.rel); !ok {
			t.Errorf("%s/%s is not in the backup", want.root, want.rel)
		}
	}
	for _, unwanted := range []string{"cache/cache.db", "bot/.reload-singbox"} {
		if _, ok := snap.Lookup(backup.RootData, unwanted); ok {
			t.Errorf("%s was backed up", unwanted)
		}
	}
	if snap.Manifest.PublicHost != "203.0.113.7" {
		t.Errorf("public host = %q", snap.Manifest.PublicHost)
	}

	// The accounting copy is a database, not a torn file.
	stats, _ := snap.Lookup(backup.RootConfig, backup.StatsPath)
	copyPath := filepath.Join(t.TempDir(), "stats.db")
	os.WriteFile(copyPath, stats.Data, 0o600)
	db, _ := sql.Open("sqlite", copyPath)
	defer db.Close()
	var download int
	if err := db.QueryRow(`SELECT download FROM user_stats_daily WHERE user = 'alice'`).Scan(&download); err != nil || download != 42 {
		t.Fatalf("the accounting copy reads %d, %v", download, err)
	}
}

func TestBackupRefusesAWeakPassphraseAndMixedKeys(t *testing.T) {
	asRoot(t)
	layout := deployedLayout(t)
	short := filepath.Join(t.TempDir(), "pass")
	os.WriteFile(short, []byte("short\n"), 0o600)
	args := []string{"-config-root", layout.ConfigRoot, "-data-root", layout.DataRoot, "-passphrase-file", short}
	if err := runBackup(context.Background(), &bytes.Buffer{}, args); err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Fatalf("a short passphrase: %v", err)
	}
	identity, _ := age.GenerateX25519Identity()
	args = append(args, "-recipient", identity.Recipient().String())
	if err := runBackup(context.Background(), &bytes.Buffer{}, args); err == nil {
		t.Fatal("a passphrase and a recipient were combined")
	}
}

func TestRestoreAddress(t *testing.T) {
	ctx := context.Background()
	base := func(host string) *state.State {
		d := state.Default([]string{"alice"})
		d.Bot.PublicHost = host
		return &d
	}

	// The server has the backup's address: nothing changes, nothing asked.
	onHost(t, []string{"203.0.113.7"}, nil)
	d := base("203.0.113.7")
	if moved, err := restoreAddress(ctx, nil, &bytes.Buffer{}, d, "", false); err != nil || moved != "" {
		t.Fatalf("same address: %q %v", moved, err)
	}

	// Another address, no terminal: refused with both ways out named.
	onHost(t, []string{"198.51.100.9"}, nil)
	d = base("203.0.113.7")
	_, err := restoreAddress(ctx, nil, &bytes.Buffer{}, d, "", false)
	if err == nil || !strings.Contains(err.Error(), "-public-host") || !strings.Contains(err.Error(), "-keep-address") {
		t.Fatalf("no terminal: %v", err)
	}

	// The new address from the flag; the direct subscription link follows it.
	d = base("203.0.113.7")
	d.Bot.DirectSubscriptionHost = "203.0.113.7:10873"
	d.Bot.PublicIPv4Host = "203.0.113.7"
	moved, err := restoreAddress(ctx, nil, &bytes.Buffer{}, d, "198.51.100.9", false)
	if err != nil || moved != "203.0.113.7" {
		t.Fatalf("flag: %q %v", moved, err)
	}
	if d.Bot.PublicHost != "198.51.100.9" || d.Bot.DirectSubscriptionHost != "" || d.Bot.PublicIPv4Host != "198.51.100.9" {
		t.Fatalf("bot = %+v", d.Bot)
	}

	// At a terminal: not moving, static, take the detected address.
	d = base("203.0.113.7")
	atTerminal(t, "n\n\n\n")
	var out bytes.Buffer
	moved, err = restoreAddress(ctx, newPrompt(), &out, d, "", false)
	if err != nil || moved != "203.0.113.7" || d.Bot.PublicHost != "198.51.100.9" {
		t.Fatalf("terminal: %q %v %+v\n%s", moved, err, d.Bot, out.String())
	}
	if !strings.Contains(out.String(), "new link") {
		t.Errorf("the consequence was not said:\n%s", out.String())
	}

	// A domain stays a domain.
	d = base("vpn.example.com")
	if moved, err := restoreAddress(ctx, nil, &bytes.Buffer{}, d, "", false); err != nil || moved != "" || d.Bot.PublicHost != "vpn.example.com" {
		t.Fatalf("domain: %q %v", moved, err)
	}
}
