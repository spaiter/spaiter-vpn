package external

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HashStatus is what a check concluded about one VK call link.
type HashStatus struct {
	// Status is the helper's verdict: ok, dead, captcha, limited, network or
	// error. Only "dead" is acted on; the rest are inconclusive and leave the
	// entry as it was, because a captcha says nothing about the link.
	Status string
	Detail string
}

// Dead reports whether the link is gone for good as far as this check knows.
func (h HashStatus) Dead() bool { return h.Status == "dead" }

// Conclusive reports whether the verdict says anything about the link itself.
// A rate limit or a network failure is about the check, not the link.
func (h HashStatus) Conclusive() bool { return h.Status == "ok" || h.Status == "dead" }

// HashChecker validates VK call links by running the helper that knows how to
// join one.
type HashChecker struct {
	Binary string
	log    *slog.Logger
}

// NewHashChecker builds a checker.
func NewHashChecker(binary string, log *slog.Logger) *HashChecker {
	if log == nil {
		log = slog.Default()
	}
	return &HashChecker{Binary: binary, log: log}
}

// Check validates every hash it is given and returns the verdicts by hash.
//
// A hash the helper said nothing about is absent from the result rather than
// present as unknown: the caller has to tell "checked and alive" from "not
// checked", and collapsing them would mark a pool dead whenever the helper
// crashed.
func (c *HashChecker) Check(ctx context.Context, hashes []string) (map[string]HashStatus, error) {
	if len(hashes) == 0 {
		return map[string]HashStatus{}, nil
	}
	if c.Binary == "" {
		return nil, fmt.Errorf("external: no hash-check binary configured")
	}
	if _, err := os.Stat(c.Binary); err != nil {
		return nil, fmt.Errorf("external: hash-check binary %s: %w", c.Binary, err)
	}

	// The budget grows with the pool because each link is joined in turn, and
	// joining one can take most of a minute.
	budget := HashCheckBase + time.Duration(len(hashes))*HashCheckPerHash
	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(runCtx, c.Binary, hashes...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	runErr := cmd.Run()
	// Parsed regardless of the exit status: the helper reports per-hash
	// verdicts on its way through and may well exit non-zero after finding a
	// dead link, and throwing away what it did say would waste the whole run.
	result := parseHashCheck(stdout.Bytes())
	if runErr != nil && len(result) == 0 {
		return nil, fmt.Errorf("external: %s failed with no verdicts: %w: %s",
			c.Binary, runErr, firstLine(stderr.String()))
	}
	if runErr != nil {
		c.log.Warn("the hash checker exited badly but reported some verdicts",
			"error", runErr, "verdicts", len(result))
	}
	return result, nil
}

// parseHashCheck reads the helper's protocol: one HASH_CHECK line per hash,
// pipe separated, with the detail free to contain anything including pipes.
func parseHashCheck(out []byte) map[string]HashStatus {
	result := map[string]HashStatus{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	// A detail can be long; the default 64 KiB line limit is generous but a
	// truncated line would silently drop a verdict.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "HASH_CHECK|") {
			continue
		}
		// Four fields at most, so a detail containing a pipe survives intact.
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 3 || parts[1] == "" {
			continue
		}
		status := HashStatus{Status: parts[2]}
		if len(parts) > 3 {
			status.Detail = parts[3]
		}
		result[parts[1]] = status
	}
	return result
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Timings of a pool check.
var (
	// HashCheckBase is the fixed part of the budget.
	HashCheckBase = 30 * time.Second
	// HashCheckPerHash is added for each link, which is joined in turn.
	HashCheckPerHash = 95 * time.Second
)
