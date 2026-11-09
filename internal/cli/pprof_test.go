package cli

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestServePprofServesGoroutineLeakProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logged strings.Builder
	log := slog.New(slog.NewTextHandler(&logged, nil))

	if err := servePprof(ctx, "", log); err != nil {
		t.Fatalf("empty address must disable the server, got %v", err)
	}
	if logged.Len() != 0 {
		t.Fatalf("empty address must stay silent, logged %q", logged.String())
	}

	if err := servePprof(ctx, "127.0.0.1:0", log); err != nil {
		t.Fatal(err)
	}
	// The address is only known through the log line, which is also how an
	// operator finds it.
	line := logged.String()
	i := strings.Index(line, "addr=")
	if i < 0 {
		t.Fatalf("no addr in log: %q", line)
	}
	addr := strings.TrimSpace(line[i+len("addr="):])

	for _, profile := range []string{"goroutine", "goroutineleak", "heap"} {
		resp, err := http.Get("http://" + addr + "/debug/pprof/" + profile + "?debug=1")
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d: %s", profile, resp.StatusCode, body)
		}
	}

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the root must not serve anything, got %d", resp.StatusCode)
	}
}
