package exporter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLabelsAreCachedAndFallBackToTheResourceItself(t *testing.T) {
	r := newServiceResolver(false, 50)
	// A hostname is classified by its name alone.
	if got := r.Label("cdn.googlevideo.com"); got == "" {
		t.Error("a hostname got no label")
	}
	// A documentation address resolves to nothing, so the address is the label,
	// and the second call is answered from the cache.
	first := r.Label("203.0.113.77")
	if first != "203.0.113.77" {
		t.Errorf("fallback label = %q", first)
	}
	r.mu.Lock()
	r.cache["203.0.113.77"] = "cached-service"
	r.mu.Unlock()
	if got := r.Label("203.0.113.77"); got != "cached-service" {
		t.Errorf("the cache was not used: %q", got)
	}
	// An address the lookup cannot resolve and ipinfo is off for returns "".
	if got := r.ipInfoOrg("203.0.113.77"); got != "" {
		t.Errorf("ipinfo ran while disabled: %q", got)
	}
}

func TestServiceFromNameRefusesNumericFallbacks(t *testing.T) {
	for in, want := range map[string]string{
		"host.example.org.":   "example.org",
		"1-2-3-4.example.net": "",
		"single":              "single",
		"Single":              "Single",
		"x.123.456":           "",
	} {
		if got := serviceFromName(in); got != want {
			t.Errorf("serviceFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitLinesKeepsAnUnterminatedTail(t *testing.T) {
	got := splitLines("a\nb\nlast")
	if len(got) != 3 || got[2] != "last" {
		t.Errorf("lines = %q", got)
	}
	if len(splitLines("")) != 0 || len(splitLines("\n")) != 1 {
		t.Error("empty input")
	}
}

func TestXDPCounterToleratesAMissingOrUnreadableLog(t *testing.T) {
	dir := t.TempDir()
	c := newXDPCounter(filepath.Join(dir, "absent.log"))
	c.poll() // a missing log is not an error worth stopping for
	if _, err := c.readNew(); err == nil {
		t.Error("a missing log was read")
	}
	if os.Geteuid() != 0 {
		path := filepath.Join(dir, "locked.log")
		if err := os.WriteFile(path, []byte("x\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		c = newXDPCounter(path)
		c.poll()
		if _, err := c.readNew(); err == nil {
			t.Error("an unreadable log was read")
		}
	}
	// An empty log yields nothing and no error.
	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = newXDPCounter(empty)
	if lines, err := c.readNew(); err != nil || len(lines) != 0 {
		t.Errorf("empty log = %v, %v", lines, err)
	}
}
