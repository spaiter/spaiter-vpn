package hostinfo

import (
	"os"
	"path/filepath"
	"strings"
)

// LogrotateCovers reports whether any installed logrotate configuration
// mentions the given log path.
//
// Checking for the literal path rather than trying to understand logrotate's
// grammar: a stanza names the files it rotates, so the path appearing in a
// config under /etc/logrotate.d is strong evidence, and the alternative —
// reimplementing glob and include semantics — would be a parser whose bugs
// produce confident wrong answers.
//
// Returns false when the directory cannot be read, which a caller must report
// as "could not tell" rather than "not rotated".
func LogrotateCovers(logPath string) (bool, bool) {
	return logrotateCovers("/etc/logrotate.d", logPath)
}

func logrotateCovers(dir, logPath string) (bool, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false
	}

	targets := []string{logPath, filepath.Dir(logPath) + "/*.log"}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		body := string(data)
		for _, target := range targets {
			if strings.Contains(body, target) {
				return true, true
			}
		}
	}
	return false, true
}
