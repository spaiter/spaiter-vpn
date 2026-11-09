package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestExitStatusesTellAUsageMistakeFromAFailure(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"no arguments is a usage error", nil, 2, "usage"},
		{"an unknown command is a usage error", []string{"frobnicate"}, 2, "frobnicate"},
		{"a missing flag value is reported and the usage follows", []string{"verify"}, 2, "-bundle"},
		{"a runtime failure is exit 1", []string{"verify", "-bundle", "/nonexistent/bundle.json"}, 1, "error:"},
		{"version succeeds and prints to stdout", []string{"version"}, 0, ""},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		code := run(ctx, &out, &errOut, c.args)
		if code != c.wantCode {
			t.Errorf("%s: exit %d, want %d\nstdout: %s\nstderr: %s", c.name, code, c.wantCode, out.String(), errOut.String())
			continue
		}
		if !strings.Contains(errOut.String()+out.String(), c.wantStderr) {
			t.Errorf("%s: output lacks %q\nstdout: %s\nstderr: %s", c.name, c.wantStderr, out.String(), errOut.String())
		}
	}
}

// A usage error must not repeat the sentinel's own text ("usage: usage: ...").
func TestAUsageErrorDoesNotRepeatItsOwnPrefix(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), &out, &errOut, []string{"verify"}); code != 2 {
		t.Fatalf("exit %d", code)
	}
	first := strings.SplitN(errOut.String(), "\n", 2)[0]
	if strings.HasPrefix(first, "usage: usage") || strings.HasPrefix(first, "usage:: ") {
		t.Errorf("first line = %q", first)
	}
}

// A dead VK access token is exit 3, so a wrapper can tell "a human must sign
// in again" from a retryable failure (exit 1).
func TestADeadVKAccessTokenHasItsOwnExitStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"error":{"error_code":1117,"error_msg":"expired"}}`))
	}))
	defer server.Close()

	stdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("dead-token\n")
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = stdin; r.Close() }()

	var out, errOut bytes.Buffer
	if code := run(context.Background(), &out, &errOut, []string{"vk", "mint", "-api-host", server.URL}); code != 3 {
		t.Errorf("exit %d, want 3\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "error:") {
		t.Errorf("no error line: %q", errOut.String())
	}
}
