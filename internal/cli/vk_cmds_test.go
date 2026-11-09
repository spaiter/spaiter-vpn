package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/vk"
)

func TestVKDispatch(t *testing.T) {
	var out bytes.Buffer
	if err := runVK(context.Background(), &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no subcommand: %v", err)
	}
	if err := runVK(context.Background(), &out, []string{"frobnicate"}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("unknown: %v", err)
	}
}

// fakeVKCalls answers messages.getCallToken the way VK does.
func fakeVKCalls(t *testing.T, answer string) (host string, seen *string) {
	t.Helper()
	got := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("Authorization")
		fmt.Fprint(w, answer)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, got
}

func stdinIs(t *testing.T, text string) { stdinHolds(t, text) }

func TestVKMintPrintsTheCallTokenAndKeepsTheAccessTokenOffTheCommandLine(t *testing.T) {
	host, auth := fakeVKCalls(t, `{"response":{"token":"CALLTOK","api_base_url":"https://calls.example"}}`)
	stdinIs(t, "access-secret\nignored second line\n")
	var out bytes.Buffer
	if err := runVKMint(context.Background(), &out, []string{"-api-host", host}); err != nil {
		t.Fatal(err)
	}
	if *auth != "Bearer access-secret" {
		t.Errorf("Authorization = %q", *auth)
	}
	for _, want := range []string{`"call_token": "CALLTOK"`, `"api_base_url": "https://calls.example"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "access-secret") {
		t.Error("the access token was echoed")
	}
}

func TestVKMintFailures(t *testing.T) {
	ctx := context.Background()
	stdinIs(t, "")
	if err := runVKMint(ctx, &bytes.Buffer{}, nil); err == nil || !strings.Contains(err.Error(), "no access token") {
		t.Errorf("empty stdin: %v", err)
	}

	host, _ := fakeVKCalls(t, `{"error":{"error_code":1117,"error_msg":"expired"}}`)
	stdinIs(t, "dead-token\n")
	if err := runVKMint(ctx, &bytes.Buffer{}, []string{"-api-host", host}); !errors.Is(err, vk.ErrAccessTokenExpired) {
		t.Errorf("expired token: %v", err)
	}
	host, _ = fakeVKCalls(t, `{"error":{"error_code":9,"error_msg":"flood"}}`)
	stdinIs(t, "tok\n")
	err := runVKMint(ctx, &bytes.Buffer{}, []string{"-api-host", host})
	if err == nil || errors.Is(err, vk.ErrAccessTokenExpired) {
		t.Errorf("a transient VK error must not look like an expired token: %v", err)
	}
	stdinIs(t, "tok\n")
	if err := runVKMint(ctx, &bytes.Buffer{}, []string{"-api-host", "http://127.0.0.1:1"}); err == nil {
		t.Error("an unreachable VK was fine")
	}
}

func TestFirstLineAndPromptLine(t *testing.T) {
	for in, want := range map[string]string{"tok\n": "tok", "  tok  \nmore": "tok", "tok": "tok", "": "", "\n": ""} {
		got, err := firstLine(strings.NewReader(in))
		if err != nil || got != want {
			t.Errorf("firstLine(%q) = %q, %v", in, got, err)
		}
	}
	var tty bytes.Buffer
	got, err := promptLine(&tty, bufio.NewReader(strings.NewReader(" alice \nrest")), "Login: ")
	if err != nil || got != "alice" || tty.String() != "Login: " {
		t.Errorf("promptLine = %q, %v, prompt %q", got, err, tty.String())
	}
	if got, err := promptLine(&tty, bufio.NewReader(strings.NewReader("no newline")), "> "); err != nil || got != "no newline" {
		t.Errorf("last line without a newline: %q, %v", got, err)
	}
}

func TestDescribeVKErrorSaysWhatToDo(t *testing.T) {
	captcha := describeVKError(&vk.CaptchaError{ImageURL: "https://vk.example/captcha.jpg"})
	if !strings.Contains(captcha.Error(), "https://vk.example/captcha.jpg") || !strings.Contains(captcha.Error(), "captcha") {
		t.Errorf("captcha: %v", captcha)
	}
	if got := describeVKError(fmt.Errorf("wrapped: %w", vk.ErrInvalidCredentials)); !strings.Contains(got.Error(), "login or password") {
		t.Errorf("credentials: %v", got)
	}
	plain := errors.New("network down")
	if got := describeVKError(plain); got != plain {
		t.Errorf("other errors must pass through unchanged: %v", got)
	}
}

func TestRandomDeviceIDIsHexAndDiffers(t *testing.T) {
	a, b := randomDeviceID(), randomDeviceID()
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a) || a == b {
		t.Errorf("ids %q %q", a, b)
	}
}

func TestStorePublisherReplacesOnlyItsOwnEntries(t *testing.T) {
	_, cfg := botFiles(t, "127.0.0.1:1", nil)
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	store := parts.store
	if err := store.UpdateVKHashes(func(h state.VKHashes) error {
		h["manual"] = state.VKHash{Status: "ok", ByName: "someone"}
		h["old"] = state.VKHash{Status: "ok", ByName: "vkcalls-server", Added: "2026-01-01T00:00:00Z"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pub := &storePublisher{store: store, name: "vkcalls-server"}
	if err := pub.Publish(context.Background(), []string{"old", "new"}); err != nil {
		t.Fatal(err)
	}
	// A call that was already published keeps the time it first appeared.
	if kept, _ := store.VKHashes(); kept["old"].Added != "2026-01-01T00:00:00Z" {
		t.Errorf("Added was reset to %q", kept["old"].Added)
	}
	if err := pub.Publish(context.Background(), []string{"new"}); err != nil {
		t.Fatal(err)
	}
	pool, _ := store.VKHashes()
	if _, ok := pool["manual"]; !ok || pool["manual"].ByName != "someone" {
		t.Error("someone else's entry was touched")
	}
	if _, ok := pool["old"]; ok {
		t.Error("a dropped call stayed in the pool")
	}
	if e := pool["new"]; e.Status != "ok" || e.ByName != "vkcalls-server" || e.Added == "" || e.Checked == "" {
		t.Errorf("new entry = %+v", e)
	}
	// A call that stays keeps the time it first appeared.
	first := pool["new"].Added
	pub.Publish(context.Background(), []string{"new"})
	if again, _ := store.VKHashes(); again["new"].Added != first {
		t.Errorf("Added moved from %q to %q", first, again["new"].Added)
	}
}

func TestPassAccessTokenReadsTheFirstLineThroughSudo(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	script := func(body string) {
		os.WriteFile(filepath.Join(bin, "sudo"), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	script(`[ "$1" = -n ] && [ "$3" = "services/x" ] && printf 'the-token\nmetadata\n'`)
	got, err := passAccessToken("services/x")(context.Background())
	if err != nil || got != "the-token" {
		t.Errorf("token = %q, %v", got, err)
	}
	script(`printf '\n'`)
	if _, err := passAccessToken("services/x")(context.Background()); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty entry: %v", err)
	}
	script(`exit 1`)
	if _, err := passAccessToken("services/x")(context.Background()); err == nil || !strings.Contains(err.Error(), "read access token") {
		t.Errorf("failing pass: %v", err)
	}
}

func TestReloginRunnerRunsTheConfiguredHelper(t *testing.T) {
	ctx := context.Background()
	if err := reloginRunner("", quietLog)(ctx); err == nil {
		t.Error("no helper configured was fine")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	helper := filepath.Join(dir, "relogin.sh")
	os.WriteFile(helper, []byte("touch "+marker+"\n"), 0o644)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("the helper is a bash script and there is no bash here")
	}
	if err := reloginRunner(helper, quietLog)(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the helper did not run")
	}
	os.WriteFile(helper, []byte("exit 3\n"), 0o644)
	if err := reloginRunner(helper, quietLog)(ctx); err == nil {
		t.Error("a failing helper was fine")
	}
	_ = os.Stdin
}
