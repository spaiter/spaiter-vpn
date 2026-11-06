package backup

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// Paths inside the roots. Kept here, beside the code that writes them, so a
// restore reads exactly what a backup wrote.
const (
	DesiredPath = "desired.json"
	ConfigPath  = "deployment/config.json"
	SecretsPath = "deployment/secrets/secrets.json"
	StatsPath   = "deployment/user_stats.db"
	credentials = "credentials"
	botData     = "bot"
	cacheData   = "cache"
)

// Collect gathers what a new server needs: the desired state, the stored
// credentials, the core's configuration and handover (which together hold
// every key and every user, including the ones the bot added), the traffic
// accounting, the bot's state, the core's cache (ACME account and
// certificates) and the WG-over-VK relay's passwords.
//
// Everything else bootstrap renders from these on the new host, for that host:
// the compose project, the units, the firewall rules, the receipt. Copying them
// would carry the old host's account ids and rule ownership into the new one.
func Collect(layout discover.Layout, version string) (*Snapshot, error) {
	desired, err := state.Load(layout.DesiredPath())
	if err != nil {
		return nil, fmt.Errorf("read the desired state (is this a bootstrap-managed server?): %w", err)
	}
	host, _ := os.Hostname()
	snap := &Snapshot{Manifest: Manifest{
		Created: time.Now().UTC().Truncate(time.Second), Hostname: host,
		Version: version, PublicHost: desired.Bot.PublicHost,
	}}

	for rel, source := range map[string]string{
		DesiredPath: layout.DesiredPath(),
		ConfigPath:  layout.ConfigPath(),
		SecretsPath: layout.SecretsPath(),
	} {
		if _, err := os.Stat(source); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if err := snap.Add(RootConfig, rel, source); err != nil {
			return nil, err
		}
	}
	if err := snap.AddTree(RootConfig, credentials, layout.CredentialDir(), nil); err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	if err := addDatabase(snap, RootConfig, StatsPath, filepath.Join(layout.DeploymentDir(), "user_stats.db")); err != nil {
		return nil, fmt.Errorf("traffic accounting: %w", err)
	}
	// The reload markers are requests to a process on the old host, not state.
	if err := snap.AddTree(RootData, botData, layout.BotDataDir(), func(rel string) bool {
		return strings.HasPrefix(rel, ".reload-")
	}); err != nil {
		return nil, fmt.Errorf("bot state: %w", err)
	}
	// The core's cache.db is its own runtime cache and is rebuilt; what is
	// worth keeping is the ACME account and certificates, which a fresh
	// issuance would otherwise have to win again against a rate limit.
	if err := snap.AddTree(RootData, cacheData, layout.CacheDir(), func(rel string) bool {
		return rel == "cache.db" || isDatabaseSidecar(rel)
	}); err != nil {
		return nil, fmt.Errorf("core cache: %w", err)
	}
	if dir := desired.Bot.WDTTConfigDirectory; dir != "" {
		if err := snap.AddTree(RootRelay, ".", dir, nil); err != nil {
			return nil, fmt.Errorf("relay passwords: %w", err)
		}
	}
	return snap, nil
}

// addDatabase takes a consistent copy of a live SQLite database. Copying the
// file while the core writes it can capture a torn page; VACUUM INTO reads
// through SQLite and works on a read-only connection.
func addDatabase(snap *Snapshot, root Root, rel, source string) error {
	info, err := os.Stat(source)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "spaiter-vpn-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	copyPath := filepath.Join(tmp, "copy.db")

	db, err := sql.Open("sqlite", "file:"+source+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("VACUUM INTO ?", copyPath); err != nil {
		return fmt.Errorf("copy %s: %w", source, err)
	}
	data, err := os.ReadFile(copyPath)
	if err != nil {
		return err
	}
	return snap.AddData(root, rel, info.Mode().Perm(), data)
}

func isDatabaseSidecar(rel string) bool {
	return strings.HasSuffix(rel, "-wal") || strings.HasSuffix(rel, "-shm") || strings.HasSuffix(rel, "-journal")
}
