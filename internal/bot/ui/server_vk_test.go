package ui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/loops"
	"github.com/spaiter/spaiter-vpn/internal/control"
)

// scriptedControl answers each operation with a fixed response or error.
type scriptedControl struct {
	responses map[control.Operation]control.Response
	err       error
	seen      []control.Request
}

func (s *scriptedControl) Do(_ context.Context, r control.Request) (control.Response, error) {
	s.seen = append(s.seen, r)
	return s.responses[r.Operation], s.err
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestServerMenuRendersStatusAndGenerationsAndSurvivesDaemonFailures(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	ctl := &scriptedControl{responses: map[control.Operation]control.Response{
		control.OpStatus: {OK: true, Result: raw(map[string]any{
			"tier": "ab", "image": "repo/core:" + strings.Repeat("x", 100), "seedUsers": 2, "generation": 7, "transaction": "tx-7",
			"services":      []map[string]string{{"Service": "sing-box", "State": "running", "Health": "healthy"}},
			"servicesError": "docker said no",
		})},
		control.OpGenerations: {OK: true, Result: raw([]map[string]any{{"Sequence": 7, "CommittedAt": "2026-11-07T10:00:00Z extra"}})},
	}}
	u.SetControl(ctl)

	u.handleServer(ctx, callback(1, cbServer), 1, cbServer)
	edit := telegram.last(t)
	text, _ := edit["text"].(string)
	for _, want := range []string{"generation 7 (tx-7)", "tier ab, 2 seed users", "sing-box", "running healthy", "services: docker said no", "…"} {
		if !strings.Contains(text, want) {
			t.Errorf("status lacks %q:\n%s", want, text)
		}
	}
	u.handleServer(ctx, callback(1, cbGens), 1, cbGens)
	if text, _ = telegram.last(t)["text"].(string); !strings.Contains(text, "7  2026-11-07T10:00:0…") || strings.Contains(text, "extra") {
		t.Errorf("generations:\n%s", text)
	}

	// A daemon that refuses, errors or is absent is reported, not swallowed.
	ctl.responses[control.OpStatus] = control.Response{Error: "no access for you"}
	u.handleServer(ctx, callback(1, cbServer), 1, cbServer)
	if text, _ = telegram.last(t)["text"].(string); !strings.Contains(text, "no access for you") {
		t.Errorf("refusal not shown: %q", text)
	}
	ctl.err = errors.New("socket gone")
	u.handleServer(ctx, callback(1, cbGens), 1, cbGens)
	if text, _ = telegram.last(t)["text"].(string); !strings.Contains(text, "socket gone") {
		t.Errorf("transport error not shown: %q", text)
	}
	u.control = nil
	u.handleServer(ctx, callback(1, cbServer), 1, cbServer)
	if text, _ = telegram.last(t)["text"].(string); text != u.text("srv_unavailable") {
		t.Errorf("no daemon: %q", text)
	}
}

func TestServerConfirmAbortAndRollbackGoThroughTheTicket(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	ctl := &scriptedControl{responses: map[control.Operation]control.Response{
		control.OpPrepare: {OK: true, Result: raw(map[string]any{"id": "tick", "plan": map[string]any{"mode": "migrate"}})},
		control.OpCommit:  {Error: "health wait failed"},
		control.OpCancel:  {OK: true},
	}}
	u.SetControl(ctl)

	u.handleServer(ctx, callback(1, cbRollback), 1, cbRollback)
	if len(ctl.seen) != 1 || ctl.seen[0].Change == nil || ctl.seen[0].Change.Kind != control.ChangeRollback {
		t.Fatalf("rollback did not prepare: %+v", ctl.seen)
	}
	if text, _ := telegram.last(t)["text"].(string); !strings.Contains(text, "mode: migrate") {
		t.Errorf("plan not shown: %q", text)
	}

	u.handleServer(ctx, callback(1, cbConfirm+"tick"), 1, cbConfirm+"tick")
	if last := ctl.seen[len(ctl.seen)-1]; last.Operation != control.OpCommit || last.Ticket != "tick" {
		t.Errorf("confirm sent %+v", last)
	}
	if text, _ := telegram.last(t)["text"].(string); !strings.Contains(text, "health wait failed") {
		t.Errorf("a failed commit must say why: %q", text)
	}

	u.handleServer(ctx, callback(1, cbAbort+"tick"), 1, cbAbort+"tick")
	if last := ctl.seen[len(ctl.seen)-1]; last.Operation != control.OpCancel || last.Ticket != "tick" {
		t.Errorf("abort sent %+v", last)
	}
	if text, _ := telegram.last(t)["text"].(string); text != u.text("srv_cancelled") {
		t.Errorf("abort text %q", text)
	}
	u.handleServer(ctx, callback(1, "a:bogus"), 1, "a:bogus")
	if text, _ := telegram.last(t)["text"].(string); text != u.label("unavailable") {
		t.Errorf("unknown server callback: %q", text)
	}
}

func TestPrepareRefusesWhatTheDaemonWouldAndWhatItCannotUse(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	ctl := &scriptedControl{responses: map[control.Operation]control.Response{
		control.OpPrepare: {OK: true, Result: raw(map[string]any{"plan": "no id here"})},
	}}
	u.SetControl(ctl)

	// An invalid change is stopped before the daemon is asked.
	u.prepare(ctx, 1, control.Change{Kind: control.ChangeImage})
	if len(ctl.seen) != 0 {
		t.Errorf("an invalid change reached the daemon: %+v", ctl.seen)
	}
	// A reply with no ticket must not produce a confirm button for nothing.
	u.prepare(ctx, 1, control.Change{Kind: control.ChangeRollback})
	sent := telegram.last(t)
	if text, _ := sent["text"].(string); !strings.Contains(text, "no ticket") || sent["reply_markup"] != nil {
		t.Errorf("ticketless reply: %v", sent)
	}
}

func TestRenderingToleratesWhatTheDaemonSends(t *testing.T) {
	if got := renderStatus(json.RawMessage(`not json`)); got != "not json" {
		t.Errorf("renderStatus = %q", got)
	}
	if got := renderGenerations(json.RawMessage(`{}`)); got != "{}" {
		t.Errorf("renderGenerations = %q", got)
	}
	if got := renderPlan(json.RawMessage(`[`)); got != "unreadable plan" {
		t.Errorf("renderPlan = %q", got)
	}
	var many []map[string]any
	for i := 0; i < 20; i++ {
		many = append(many, map[string]any{"mutates": true, "summary": "step"})
	}
	plan := renderPlan(raw(map[string]any{"mode": "m", "actions": many}))
	if strings.Count(plan, "* step") != 12 || !strings.Contains(plan, "…") {
		t.Errorf("a long plan must be cut at 12 actions:\n%s", plan)
	}
	if got := codeBlock("a ``` b"); strings.Count(got, "```") != 2 {
		t.Errorf("a code fence inside planner text escaped the block: %q", got)
	}
	if clip("абвгд", 3) != "аб…" || clip("абв", 3) != "абв" {
		t.Error("clip must count characters, not bytes")
	}
	if argAt([]string{"a"}, 3) != "" || argAt([]string{"a"}, 0) != "a" {
		t.Error("argAt")
	}
}

func TestWebLoginIsAdminOnlyAndHandsOutTheLinkOnce(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	u.onWebLogin(ctx, nil, message(1, "/weblogin"))
	if got := telegram.messagesTo(1); got[len(got)-1] != u.text("web_unavailable") {
		t.Errorf("no minter: %q", got[len(got)-1])
	}
	u.SetWebLogin(func() (string, error) { return "https://panel.example/login?t=ONETIME", nil })
	u.onWebLogin(ctx, nil, message(1, "/weblogin"))
	if got := telegram.messagesTo(1); !strings.Contains(got[len(got)-1], "ONETIME") {
		t.Errorf("link not sent: %q", got[len(got)-1])
	}
	u.onWebLogin(ctx, nil, message(99, "/weblogin"))
	for _, m := range telegram.messagesTo(99) {
		if strings.Contains(m, "ONETIME") {
			t.Fatal("a non-admin was handed the web login link")
		}
	}
	u.SetWebLogin(func() (string, error) { return "", errors.New("mint failed") })
	u.onWebLogin(ctx, nil, message(1, "/weblogin"))
	if got := telegram.messagesTo(1); !strings.Contains(got[len(got)-1], "mint failed") {
		t.Errorf("mint failure: %q", got[len(got)-1])
	}
}

type fakeValidator struct {
	verdict map[string]external.HashStatus
	err     error
}

func (f fakeValidator) Check(_ context.Context, hashes []string) (map[string]external.HashStatus, error) {
	return f.verdict, f.err
}

func TestVKHashPoolCommands(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	say := func(text string) string {
		u.onVKHash(ctx, nil, message(1, text))
		got := telegram.messagesTo(1)
		return got[len(got)-1]
	}

	if got := say("/vkhash"); !strings.Contains(got, u.label("vk_pool_title")) {
		t.Errorf("empty list: %q", got)
	}
	if got := say("/vkhash bogus"); got != u.label("usage_vkhash") {
		t.Errorf("unknown action: %q", got)
	}
	for _, usage := range []string{"/vkhash add", "/vkhash del"} {
		if got := say(usage); got != u.label("usage_vkhash") {
			t.Errorf("%q: %q", usage, got)
		}
	}

	// A link is validated before it joins the pool.
	if got := say("/vkhash add https://vk.com/call/join/GOODCODE1"); !strings.Contains(got, u.label("vk_no_checker")) && !strings.Contains(got, "vk_rejected") {
		// without a validator the submit is rejected, never silently accepted
		if hashes, _ := u.store.VKHashes(); len(hashes) != 0 {
			t.Errorf("an unvalidated link entered the pool: %v", hashes)
		}
	}
	u.SetValidator(fakeValidator{verdict: map[string]external.HashStatus{"GOODCODE1": {Status: "ok", Detail: "live"}}})
	say("/vkhash add https://vk.com/call/join/GOODCODE1")
	pool, _ := u.store.VKHashes()
	if e := pool["GOODCODE1"]; e.Status != "ok" || e.By != 1 {
		t.Fatalf("pool = %+v (the submitter must be recorded so they can be told when it dies)", pool)
	}
	if got := say("/vkhash list"); !strings.Contains(got, "GOODCODE1") {
		t.Errorf("list: %q", got)
	}
	if got := say("/vkhash add GOODCODE1"); got != u.text("vk_already") {
		t.Errorf("already present: %q", got)
	}
	say("/vkhash del https://vk.com/call/join/GOODCODE1")
	if pool, _ = u.store.VKHashes(); len(pool) != 0 {
		t.Errorf("del left %v", pool)
	}

	if got := say("/vkhash add https://example.org/other"); got != u.text("vk_rejected", u.label("vk_not_a_link")) {
		t.Errorf("a non-call link: %q", got)
	}
	u.SetValidator(fakeValidator{verdict: map[string]external.HashStatus{"DEADCODE1": {Status: "dead", Detail: "gone"}}})
	if got := say("/vkhash add DEADCODE1"); !strings.Contains(got, "gone") {
		t.Errorf("a dead link: %q", got)
	}
	u.SetValidator(fakeValidator{verdict: map[string]external.HashStatus{"CAPTCHA01": {Status: "captcha"}}})
	say("/vkhash add CAPTCHA01")
	if pool, _ = u.store.VKHashes(); len(pool) != 0 {
		t.Errorf("an inconclusive verdict must not add (nor remove): %v", pool)
	}
	u.SetValidator(fakeValidator{err: errors.New("helper down")})
	if got := say("/vkhash add SOMECODE01"); !strings.Contains(got, "helper down") {
		t.Errorf("validator error: %q", got)
	}
	u.SetValidator(fakeValidator{verdict: map[string]external.HashStatus{}})
	if got := say("/vkhash add NOVERDICT1"); !strings.Contains(got, u.label("vk_no_verdict")) {
		t.Errorf("no verdict: %q", got)
	}
}

type fakeChecker struct {
	summary loops.Summary
	err     error
}

func (f fakeChecker) Validate(context.Context) (loops.Summary, error) { return f.summary, f.err }

type fakeRefresher struct {
	n      int
	err    error
	reason string
}

func (f *fakeRefresher) RefreshAll(_ context.Context, reason string) (int, error) {
	f.reason = reason
	return f.n, f.err
}

func TestVKCheckAndPushConfigNeedTheirCollaborators(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	last := func() string { g := telegram.messagesTo(1); return g[len(g)-1] }

	u.onVKHash(ctx, nil, message(1, "/vkhash check"))
	if last() != u.label("vk_no_checker") {
		t.Errorf("no checker: %q", last())
	}
	u.SetPoolChecker(fakeChecker{summary: loops.Summary{Checked: 5, Live: 4, NewlyDead: []string{"a"}, Pruned: []string{"b", "c"}}})
	u.onVKHash(ctx, nil, message(1, "/vkhash check"))
	if last() != u.text("vk_checked", 5, 4, 1, 2) {
		t.Errorf("summary: %q", last())
	}
	u.SetPoolChecker(fakeChecker{err: errors.New("helper timeout")})
	u.onVKHash(ctx, nil, message(1, "/vkhash check"))
	if !strings.Contains(last(), "helper timeout") {
		t.Errorf("checker error: %q", last())
	}

	u.onPushConfig(ctx, nil, message(1, "/pushcfg new server"))
	if last() != u.label("unavailable") {
		t.Errorf("no refresher: %q", last())
	}
	r := &fakeRefresher{n: 3}
	u.SetRefresher(r)
	u.onPushConfig(ctx, nil, message(1, "/pushcfg new server address"))
	if r.reason != "new server address" || last() != u.text("pushed", 3) {
		t.Errorf("reason=%q reply=%q", r.reason, last())
	}
	r.err = errors.New("rebuild failed")
	u.onPushConfig(ctx, nil, message(1, "/pushcfg"))
	if !strings.Contains(last(), "rebuild failed") {
		t.Errorf("refresher error: %q", last())
	}
}

func TestVKReloginCodeOnlyWhileTheHelperWaits(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	dir := t.TempDir()
	u.cfg.Paths.DataDir = dir
	status, code := u.cfg.Paths.VKReloginStatus(), u.cfg.Paths.VKReloginCode()
	os.MkdirAll(filepath.Dir(status), 0o755)
	last := func() string { g := telegram.messagesTo(1); return g[len(g)-1] }

	u.onVKCode(ctx, nil, message(1, "/vkcode"))
	if last() != u.label("usage_vkcode") {
		t.Errorf("no code: %q", last())
	}
	u.onVKCode(ctx, nil, message(1, "/vkcode 12ab56"))
	if last() != u.label("vk_code_bad") {
		t.Errorf("a non-numeric code: %q", last())
	}
	u.onVKCode(ctx, nil, message(1, "/vkcode 123456"))
	if last() != u.label("vk_code_not_waiting") {
		t.Errorf("not waiting: %q", last())
	}
	if _, err := os.Stat(code); err == nil {
		t.Fatal("a code was written while no relogin was waiting")
	}

	os.WriteFile(status, []byte("awaiting-code\n"), 0o600)
	u.onVKCode(ctx, nil, message(1, "/vkcode 123456"))
	if data, err := os.ReadFile(code); err != nil || strings.TrimSpace(string(data)) != "123456" {
		t.Errorf("code file: %q %v", data, err)
	}
	if info, _ := os.Stat(code); info.Mode().Perm() != 0o600 {
		t.Errorf("the code file is %v: it finishes a sign-in", info.Mode().Perm())
	}

	// A bare six-digit message from an admin is the code; from anyone else, nothing.
	os.Remove(code)
	u.onUpdate(ctx, u.client, message(99, "654321"))
	if _, err := os.Stat(code); err == nil {
		t.Fatal("a stranger's six digits became the VK code")
	}
	u.onUpdate(ctx, u.client, message(1, "654321"))
	if data, _ := os.ReadFile(code); strings.TrimSpace(string(data)) != "654321" {
		t.Errorf("admin free-text code: %q", data)
	}
	for in, want := range map[string]string{"123456": "123456", " 123456\n": "123456", "12345": "", "1234567": "", "123 456": "", "code 123456": "", "": ""} {
		if sixDigits(in) != want {
			t.Errorf("sixDigits(%q) = %q", in, sixDigits(in))
		}
	}
}

func TestClaimThroughTheChatAdoptsOnlyWithTheRightCode(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()

	u.onClaim(ctx, nil, message(5, "/claim"))
	u.onClaim(ctx, nil, message(5, "/claim WRONG-CODE-1"))
	if u.access.IsAdmin(5) {
		t.Fatal("adopted without a valid code")
	}
	for _, m := range telegram.messagesTo(5) {
		if m != u.text("claim_refused") {
			t.Errorf("refusal text %q", m)
		}
	}
	code, err := u.store.IssueClaim(15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Typed by hand, so the case does not matter.
	u.onClaim(ctx, nil, message(5, "/claim "+strings.ToLower(code)))
	if !u.access.IsAdmin(5) {
		t.Fatal("the issued code did not adopt")
	}
	u.onClaim(ctx, nil, message(6, "/claim "+code))
	if u.access.IsAdmin(6) {
		t.Fatal("the code worked twice")
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := idList(nil, nil); got != "—" {
		t.Errorf("empty idList = %q", got)
	}
	if got := idList([]int64{4, 2}, func(id int64) string { return "n" }); got != "`4` n\n`2` n\n" {
		t.Errorf("idList = %q", got)
	}
	dir := t.TempDir()
	u, _, _ := serverUI(t)
	u.cfg.Paths.APKVersion = ""
	if apkFilename(u.cfg) != "client.apk" {
		t.Error("unversioned name")
	}
	u.cfg.Paths.APKVersion = "0.1.7"
	if apkFilename(u.cfg) != "client-0.1.7.apk" {
		t.Error("versioned name")
	}
	u.cfg.Paths.APK = filepath.Join(dir, "a.apk")
	apk := NewAPK(u.cfg, u.store, quiet())
	apk = NewAPK(u.cfg, u.store, quiet())
	if apk.Available() {
		t.Error("a missing APK reported available")
	}
	if _, err := apk.cacheKey(); err == nil {
		t.Error("cacheKey of a missing file")
	}
	os.WriteFile(u.cfg.Paths.APK, []byte("x"), 0o644)
	k1, err := apk.cacheKey()
	if err != nil || !apk.Available() {
		t.Fatalf("%q %v", k1, err)
	}
	os.WriteFile(u.cfg.Paths.APK, []byte("xy"), 0o644)
	if k2, _ := apk.cacheKey(); k2 == k1 {
		t.Error("a rebuilt APK kept the same cache key, so users would get the stale upload")
	}
}
