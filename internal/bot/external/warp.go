// Package external runs the two helper binaries the bot cannot do without.
//
// Both are cores built elsewhere, not this binary: registering a Cloudflare
// account speaks a protocol the installer has no business implementing, and
// validating a VK call link needs the client half of that transport.
package external

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// WARPRegistrar mints Cloudflare MASQUE accounts by running a core that knows
// how to register one.
//
// The account has to be minted here rather than by the client: a client behind
// a national whitelist cannot reach the registration API at all, which is the
// situation the whole path exists for. So it is registered on this host and
// baked into the config the user receives.
type WARPRegistrar struct {
	// Binary is a core built with the MASQUE outbound.
	Binary string
	// Config renders the throwaway config that performs one registration.
	Config func(cacheDB string) any
	log    *slog.Logger
}

// NewWARPRegistrar builds a registrar.
func NewWARPRegistrar(binary string, config func(cacheDB string) any, log *slog.Logger) *WARPRegistrar {
	if log == nil {
		log = slog.Default()
	}
	return &WARPRegistrar{Binary: binary, Config: config, log: log}
}

// accountPattern finds the minted account inside the core's cache file.
//
// The cache is a binary database and the account is a JSON object embedded in
// it, so it is matched rather than parsed: requiring both private_key and ipv4
// inside one brace-free span is what distinguishes the finished account from
// the other JSON the file holds.
var accountPattern = regexp.MustCompile(`\{[^{}]*"private_key"[^{}]*"ipv4"[^{}]*\}`)

// Register runs the helper until it has written an account, and returns it as
// the raw object, which is what goes into a client config unchanged.
func (w *WARPRegistrar) Register(ctx context.Context) (json.RawMessage, error) {
	if w.Binary == "" {
		return nil, fmt.Errorf("external: no WARP binary configured")
	}
	if _, err := os.Stat(w.Binary); err != nil {
		return nil, fmt.Errorf("external: WARP binary %s: %w", w.Binary, err)
	}

	dir, err := os.MkdirTemp("", "warpreg-")
	if err != nil {
		return nil, fmt.Errorf("external: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	cacheDB := filepath.Join(dir, "c.db")
	configPath := filepath.Join(dir, "reg.json")
	rendered, err := json.Marshal(w.Config(cacheDB))
	if err != nil {
		return nil, fmt.Errorf("external: render registration config: %w", err)
	}
	if err := os.WriteFile(configPath, rendered, 0o600); err != nil {
		return nil, fmt.Errorf("external: write registration config: %w", err)
	}

	// Its own context: the helper is killed as soon as the account appears,
	// and it would otherwise keep running a tunnel nobody asked for.
	runCtx, cancel := context.WithTimeout(ctx, WARPRegisterTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, w.Binary, "run", "-c", configPath)
	// Its output is a running core's log, not a result; the result is the file.
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("external: start %s: %w", w.Binary, err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	deadline := time.Now().Add(WARPRegisterTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(WARPPollInterval):
		}

		blob, err := os.ReadFile(cacheDB)
		if err != nil {
			continue // not written yet
		}
		match := accountPattern.Find(blob)
		if match == nil {
			continue
		}
		var probe struct {
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal(match, &probe); err != nil || probe.PrivateKey == "" {
			continue // a partially written record; look again
		}
		w.log.Info("registered a WARP account")
		return json.RawMessage(match), nil
	}
	return nil, fmt.Errorf("external: %s produced no account within %s", w.Binary, WARPRegisterTimeout)
}

// Timings of the registration, named so a caller can reason about the cost.
var (
	// WARPRegisterTimeout bounds one registration. Cloudflare usually answers
	// in a few seconds; the helper is killed either way.
	WARPRegisterTimeout = 30 * time.Second
	// WARPPollInterval is how often the cache file is checked.
	WARPPollInterval = 500 * time.Millisecond
)
