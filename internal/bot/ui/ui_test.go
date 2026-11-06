package ui

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-telegram/bot/models"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return store
}

func newAccess(t *testing.T) (*Access, *state.Store) {
	t.Helper()
	store := newStore(t)
	return NewAccess(store, quiet()), store
}

// TestNobodyBecomesAdminByMessagingFirst: adoption needs the code issued on
// the server, not being the first to find the bot.
func TestNobodyBecomesAdminByMessagingFirst(t *testing.T) {
	access, store := newAccess(t)
	if access.IsAdmin(4242) || access.HasAdmin() {
		t.Fatal("the first caller became admin")
	}
	code, err := store.IssueClaim(15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if access.Claim("WRONG-CODE-0000", 7) || access.IsAdmin(7) {
		t.Fatal("a wrong code was accepted")
	}
	if !access.Claim(strings.ToLower(code), 4242) || !access.IsAdmin(4242) {
		t.Fatal("the issued code did not adopt the deployment")
	}
	if access.Claim(code, 9) || access.IsAdmin(9) {
		t.Fatal("a claim code adopted the deployment twice")
	}
}

// TestTheClaimCodeIsNotARace: two callers presenting the code together must
// not both be granted the role.
func TestTheClaimCodeIsNotARace(t *testing.T) {
	access, store := newAccess(t)
	code, err := store.IssueClaim(15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	granted := make([]bool, 8)
	for i := range granted {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			granted[i] = access.Claim(code, int64(100+i))
		}()
	}
	close(start)
	wg.Wait()
	claimed := 0
	for _, ok := range granted {
		if ok {
			claimed++
		}
	}
	admins, _ := store.Admins()
	if claimed != 1 || len(admins) != 1 {
		t.Errorf("%d callers claimed, admins = %v", claimed, admins)
	}
}

// TestAClaimCodeExpiresAndCannotBeGuessed.
func TestAClaimCodeExpiresAndCannotBeGuessed(t *testing.T) {
	store := newStore(t)
	now := time.Now()
	code, err := store.IssueClaim(time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.Claim(code, 1, now.Add(2*time.Minute)); ok {
		t.Fatal("an expired code was accepted")
	}
	code, _ = store.IssueClaim(time.Minute, now)
	for i := 0; i < state.MaxClaimAttempts; i++ {
		if ok, _ := store.Claim("AAAA-AAAA-AAAA", 1, now); ok {
			t.Fatal("a guess was accepted")
		}
	}
	if ok, _ := store.Claim(code, 1, now); ok {
		t.Fatal("the code still worked after the guess limit")
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), "claim.json")); !os.IsNotExist(err) {
		t.Fatal("an exhausted claim was not destroyed")
	}
}

// TestAnUnreadableAdminListRefuses is the important failure direction. Treating
// a read error as "no admins yet" would hand the role to whoever asked next.
func TestAnUnreadableAdminListRefuses(t *testing.T) {
	store := newStore(t)
	if err := os.WriteFile(filepath.Join(store.Dir(), "admins.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	access := NewAccess(store, quiet())

	if access.IsAdmin(4242) {
		t.Error("an unreadable admin list granted the role")
	}
	if access.IsAllowed(4242) {
		t.Error("an unreadable admin list granted access")
	}
}

func TestWhitelistGrantsAndRevokes(t *testing.T) {
	access, store := newAccess(t)
	if err := store.AddAdmin(1); err != nil { // so 42 is not the bootstrap admin
		t.Fatal(err)
	}

	if access.IsAllowed(42) {
		t.Fatal("an unknown user was allowed")
	}
	access.RequestAccess(42)
	if !slices.Contains(access.Pending(), int64(42)) {
		t.Error("the request was not recorded")
	}

	if err := access.Approve(42); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !access.IsAllowed(42) {
		t.Error("an approved user is not allowed")
	}
	// Approval clears the request, or the admin's screen keeps asking.
	if slices.Contains(access.Pending(), int64(42)) {
		t.Error("the request outlived its approval")
	}

	if err := access.Revoke(42); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if access.IsAllowed(42) {
		t.Error("a revoked user is still allowed")
	}
}

func TestRejectingDoesNotGrant(t *testing.T) {
	access, store := newAccess(t)
	if err := store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	access.RequestAccess(42)

	if err := access.Reject(42); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if access.IsAllowed(42) {
		t.Error("a rejected user was allowed")
	}
	if slices.Contains(access.Pending(), int64(42)) {
		t.Error("the request was not cleared")
	}
}

func TestDisplayNameFallsBackSensibly(t *testing.T) {
	access, _ := newAccess(t)
	cases := []struct {
		user state.User
		want string
	}{
		{state.User{ID: 1, FirstName: "Ann", LastName: "Lee", Username: "ann"}, "Ann Lee @ann"},
		{state.User{ID: 2, FirstName: "Ann"}, "Ann"},
		{state.User{ID: 3, Username: "ann"}, "@ann"},
		{state.User{ID: 4}, ""},
	}
	for _, c := range cases {
		access.Register(c.user)
		if got := access.DisplayName(c.user.ID); got != c.want {
			t.Errorf("DisplayName(%d) = %q, want %q", c.user.ID, got, c.want)
		}
	}
}

// --- gating ---

// TestEverySelfServiceButtonIsGated enumerates the callback data the keyboards
// actually produce and insists each one is either gated or deliberately not.
//
// This is the test that catches the dangerous mistake: adding a button that
// hands out a configuration and forgetting to gate it. A button missing from
// someone's keyboard is still callable by anyone who knows its data.
func TestEverySelfServiceButtonIsGated(t *testing.T) {
	// Actions that hand out access to the VPN, or anything derived from it.
	gated := []string{
		cbGetConfig, cbAllMethods, cbMyStats, cbAPK,
		cbPick + "i:vless-reality-in", cbGen + "i:vless-reality-in",
		cbPick + "e:awg-in", cbGen + "e:awg-in",
		cbPick + "w:warp", cbGen + "w:warp",
		cbPick + "v:wdtt", cbGen + "v:wdtt",
	}
	for _, data := range gated {
		if !needsApproval(data) {
			t.Errorf("%q hands out access and is not gated", data)
		}
	}

	// Navigation and admin actions. The admin ones are not in this gate because
	// they have their own, stricter check at the point of use.
	ungated := []string{cbMenu, cbUsers, cbAllStats, cbAccess, cbWL + "add:42"}
	for _, data := range ungated {
		if needsApproval(data) {
			t.Errorf("%q is gated by approval, which is the wrong check for it", data)
		}
	}
}

// TestTheMainMenuHidesAdminRows: not the authority -- every admin branch checks
// again -- but a user who can see the buttons will press them and be refused,
// which reads as a broken bot.
func TestTheMainMenuHidesAdminRows(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	store := newStore(t)
	if err := store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	u := New(cfg, nil, NewAccess(store, quiet()), store, quiet())

	ordinary := flatten(u.mainMenu(42))
	for _, data := range []string{cbUsers, cbAllStats, cbAccess} {
		if slices.Contains(ordinary, data) {
			t.Errorf("an ordinary user was shown %q", data)
		}
	}

	admin := flatten(u.mainMenu(1))
	for _, data := range []string{cbUsers, cbAllStats, cbAccess} {
		if !slices.Contains(admin, data) {
			t.Errorf("the admin was not shown %q", data)
		}
	}
}

// TestTheMainMenuDoesNotOfferVKSubmission keeps the public call-link intake
// retired. Administrators can still maintain the pool explicitly with
// /vkhash, but ordinary users should not be prompted to create persistent VK
// calls for the service.
func TestTheMainMenuDoesNotOfferVKSubmission(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	store := newStore(t)
	if err := store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	u := New(cfg, nil, NewAccess(store, quiet()), store, quiet())

	for _, uid := range []int64{1, 42} {
		if slices.Contains(flatten(u.mainMenu(uid)), "addvk") {
			t.Errorf("user %d was offered the retired VK submission action", uid)
		}
	}
}

// TestTheMenuOpensTheMiniAppOnlyWhereOneIsServed: the button must point at a
// public HTTPS address or not exist, because Telegram refuses anything else.
func TestTheMenuOpensTheMiniAppOnlyWhereOneIsServed(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	store := newStore(t)
	find := func(u *UI) *models.WebAppInfo {
		for _, row := range u.mainMenu(42).InlineKeyboard {
			for _, b := range row {
				if b.WebApp != nil {
					return b.WebApp
				}
			}
		}
		return nil
	}
	if got := find(New(cfg, nil, NewAccess(store, quiet()), store, quiet())); got == nil || got.URL != "https://sub.example.com/app/" {
		t.Errorf("the menu does not open the app on the subscription host: %+v", got)
	}
	cfg.WebApp.Disabled = true
	if got := find(New(cfg, nil, NewAccess(store, quiet()), store, quiet())); got != nil {
		t.Errorf("a disabled app still has a button: %+v", got)
	}
}

// TestThePendingCountReachesTheAdmin: an access request that shows up nowhere
// is a user waiting forever.
func TestThePendingCountReachesTheAdmin(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	store := newStore(t)
	if err := store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	access := NewAccess(store, quiet())
	u := New(cfg, nil, access, store, quiet())

	access.RequestAccess(42)
	access.RequestAccess(43)

	var found string
	for _, row := range u.mainMenu(1).InlineKeyboard {
		for _, button := range row {
			if button.CallbackData == cbAccess {
				found = button.Text
			}
		}
	}
	if !strings.Contains(found, "(2)") {
		t.Errorf("the access button reads %q, without the two waiting users", found)
	}
}

func flatten(markup *models.InlineKeyboardMarkup) []string {
	var out []string
	for _, row := range markup.InlineKeyboard {
		for _, button := range row {
			out = append(out, button.CallbackData)
		}
	}
	return out
}

// --- parsing ---

func TestSplitCallbackRejectsRubbish(t *testing.T) {
	cases := []struct {
		data      string
		kind, tag string
		ok        bool
	}{
		{cbGen + "i:vless-reality-in", "i", "vless-reality-in", true},
		{cbGen + "e:awg-in", "e", "awg-in", true},
		{cbGen + "i:", "", "", false},
		{cbGen + ":tag", "", "", false},
		{cbGen + "nocolon", "", "", false},
	}
	for _, c := range cases {
		kind, tag, ok := splitCallback(c.data, cbGen)
		if ok != c.ok || (ok && (kind != c.kind || tag != c.tag)) {
			t.Errorf("splitCallback(%q) = %q, %q, %v", c.data, kind, tag, ok)
		}
	}
}

// TestNormalizeVKHashMatchesTheClient: the bot and the client core have to
// agree, or a code the bot stores is one every client fails to parse.
func TestNormalizeVKHashMatchesTheClient(t *testing.T) {
	cases := map[string]string{
		"https://vk.ru/call/join/abc-123":          "abc-123",
		"https://vk.com/call/join/abc-123":         "abc-123",
		"http://VK.RU/CALL/JOIN/abc-123":           "abc-123",
		"https://vk.ru/call/join/abc-123?from=web": "abc-123",
		"https://vk.ru/call/join/abc-123#x":        "abc-123",
		"https://vk.ru/call/join/abc-123/":         "abc-123",
		"  <https://vk.ru/call/join/abc-123>  ":    "abc-123",
		`"https://vk.ru/call/join/abc-123"`:        "abc-123",
		// A bare code is accepted: that is what a user pastes from a prior
		// message.
		"abc-123": "abc-123",
		// Any other URL is refused rather than having its last segment taken
		// for a code, which would put rubbish in everyone's subscription.
		"https://example.com/abc-123": "",
		"http://vk.ru/video/abc":      "",
		"":                            "",
		"   ":                         "",
	}
	for input, want := range cases {
		if got := NormalizeVKHash(input); got != want {
			t.Errorf("NormalizeVKHash(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestShortProfileNameFitsWhatTheClientsAccept: WireGuard and Amnezia take the
// tunnel name from the filename and allow at most 15 characters, so a full
// numeric id fails the import with "Invalid name".
func TestShortProfileNameFitsWhatTheClientsAccept(t *testing.T) {
	for _, uid := range []string{"4242", "123456789012", "1"} {
		name := shortProfileName(uid)
		if len(name) > 15 {
			t.Errorf("shortProfileName(%q) = %q, %d characters", uid, name, len(name))
		}
		for _, r := range name {
			allowed := r == '-' || r == '_' || r == '=' || r == '+' || r == '.' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !allowed {
				t.Errorf("shortProfileName(%q) = %q, which has %q in it", uid, name, r)
			}
		}
	}
}

func TestTruncateDoesNotCutMidRune(t *testing.T) {
	// Cutting a multi-byte rune in half produces a caption the API rejects
	// outright, which loses the whole message rather than its tail.
	text := strings.Repeat("конфиг", 20)
	cut := truncate(text, 10)
	if len([]rune(cut)) != 10 {
		t.Errorf("truncate gave %d runes", len([]rune(cut)))
	}
	if !utf8Valid(cut) {
		t.Error("truncate produced invalid UTF-8")
	}
	if truncate("short", 10) != "short" {
		t.Error("truncate shortened something that fits")
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func TestHumanReadsLikeASize(t *testing.T) {
	cases := map[int64]string{
		0:       "0.0B",
		512:     "512.0B",
		1024:    "1.0KB",
		1536:    "1.5KB",
		1 << 20: "1.0MB",
		1 << 30: "1.0GB",
		1 << 41: "2.0TB",
	}
	for input, want := range cases {
		if got := human(input); got != want {
			t.Errorf("human(%d) = %q, want %q", input, got, want)
		}
	}
}

// TestEveryConfiguredMessageHasItsPlaceholders guards the one mistake a format
// string makes easy: a text with the wrong number of placeholders renders with
// %!s(MISSING) in the middle of a message a user reads.
func TestEveryConfiguredMessageHasItsPlaceholders(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	expected := map[string]int{
		"access_pending": 1, "access_request": 2, "access_decided": 2,
		"pick": 2, "error": 1, "vk_rejected": 1, "my_stats": 3,
		"no_stats": 0, "ready": 2, "proto_desc": 1, "apk_unavailable": 0,
		"preparing_sub": 0, "generating": 0, "registering_warp": 0,
		"provisioning_wdtt": 0, "admin_only": 1, "claim_accepted": 0, "claim_refused": 0,
		"srv_unavailable": 0, "srv_failed": 1, "srv_status": 1, "srv_generations": 1,
		"web_link": 1, "web_unavailable": 0,
		"srv_plan": 2, "srv_applying": 0, "srv_applied": 1, "srv_cancelled": 0,
		"caption_awg": 0, "caption_warp": 0, "caption_wdtt": 0,
		"caption_json": 2, "caption_link": 2, "caption_apk": 1,
		"subscription": 3, "vk_accepted": 0, "vk_already": 0,
		"vk_try_again": 1, "vk_dead": 1, "vk_removed": 1, "vk_checked": 4,
		"whitelist": 2, "added": 2, "added_link": 3, "deleted": 2,
		"reset": 1, "pushed": 1,
		"subscription_changed": 1, "subscription_moved": 2,
		"vk_pool_dead": 1, "vk_link_died": 0, "vk_pool_low": 1,
	}
	for key, want := range expected {
		format, ok := cfg.UI.Messages[key]
		if !ok {
			t.Errorf("no default message for %q", key)
			continue
		}
		if got := countPlaceholders(format); got != want {
			t.Errorf("%q has %d placeholders, want %d: %q", key, got, want, format)
		}
	}
	for key := range cfg.UI.Messages {
		if _, known := expected[key]; !known {
			t.Errorf("%q is configured but nothing asserts its placeholders", key)
		}
	}
}

// countPlaceholders counts verbs, treating %% as the literal it is.
func countPlaceholders(format string) int {
	count := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			i++
			continue
		}
		count++
	}
	return count
}
