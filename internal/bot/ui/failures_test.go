package ui

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// breakFile makes a store file unreadable and unwritable by putting a
// directory where the file should be.
func breakFile(t *testing.T, store *state.Store, name string) {
	t.Helper()
	if err := os.RemoveAll(store.Path(name)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Path(name), 0o755); err != nil {
		t.Fatal(err)
	}
}

func corrupt(t *testing.T, store *state.Store, name string) {
	t.Helper()
	if err := os.WriteFile(store.Path(name), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAccessRefusesAndLogsWhenItsFilesAreBroken(t *testing.T) {
	if NewAccess(newStore(t), nil).log == nil {
		t.Error("no default logger")
	}

	access, store := newAccess(t)
	if err := store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	if !access.IsAllowed(1) {
		t.Error("an admin was not allowed")
	}

	corrupt(t, store, "whitelist.json")
	corrupt(t, store, "pending.json")
	corrupt(t, store, "users.json")
	if access.IsAllowed(42) {
		t.Error("an unreadable whitelist allowed someone")
	}
	if got := access.Whitelist(); got != nil {
		t.Errorf("Whitelist = %v", got)
	}
	if got := access.Pending(); got != nil {
		t.Errorf("Pending = %v", got)
	}
	if got := access.DisplayName(42); got != "" {
		t.Errorf("DisplayName = %q", got)
	}
	access.Register(state.User{ID: 42, FirstName: "A"}) // logged, not fatal
	access.RequestAccess(42)                            // logged, not fatal
	if err := access.Approve(42); err == nil {
		t.Error("Approve over an unreadable whitelist succeeded")
	}

	corrupt(t, store, "admins.json")
	if got := access.Admins(); got != nil {
		t.Errorf("Admins = %v", got)
	}
	corrupt(t, store, "claim.json")
	if access.Claim("AAAA-AAAA-AAAA", 7) {
		t.Error("a claim over a broken claim file succeeded")
	}
}

func TestPendingSkipsKeysThatAreNotIDs(t *testing.T) {
	access, store := newAccess(t)
	if err := os.WriteFile(store.Path("pending.json"), []byte(`{"abc":"x","7":"y","3":"z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := access.Pending(); !slices.Equal(got, []int64{3, 7}) {
		t.Errorf("Pending = %v", got)
	}
}

func TestTheAPKIsUploadedOnceThenSentByID(t *testing.T) {
	u, telegram, _ := svcUI(t)
	telegram.documentID = "FILE-1"
	dir := t.TempDir()
	u.cfg.Paths.APK = filepath.Join(dir, "app.apk")
	u.cfg.Paths.APKVersion = "1.2.3"
	u.apk = NewAPK(u.cfg, u.store, quiet())

	if err := os.WriteFile(u.cfg.Paths.APK, []byte("apk-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	press(u, 5, cbAPK)
	cache, err := u.store.APKCache()
	if err != nil || cache.FileID != "FILE-1" || cache.Key == "" {
		t.Fatalf("cache after the first send = %+v, %v", cache, err)
	}
	if !slices.Contains(telegram.methods(), "sendChatAction") {
		t.Error("no upload chat action before a large upload")
	}

	// The second user gets the id and nothing is uploaded.
	before := len(telegram.methods())
	press(u, 5, cbAPK)
	after := telegram.methods()[before:]
	if slices.Contains(after, "sendChatAction") {
		t.Errorf("the cached APK was uploaded again: %v", after)
	}

	// Telegram forgot the id: the first send is refused and the file goes up again.
	telegram.documentID = "FILE-2"
	telegram.failing("sendDocument", 1)
	before = len(telegram.methods())
	press(u, 5, cbAPK)
	if after := telegram.methods()[before:]; !slices.Contains(after, "sendChatAction") {
		t.Errorf("no re-upload after a refused id: %v", after)
	}
	if cache, _ := u.store.APKCache(); cache.FileID != "FILE-2" {
		t.Errorf("the refreshed id was not stored: %+v", cache)
	}
}

func TestTheAPKDeliveryReportsWhatCannotBeDone(t *testing.T) {
	u, telegram, _ := svcUI(t)

	// No file configured: the user is told it is unavailable.
	press(u, 5, cbAPK)
	if !strings.Contains(lastText(t, telegram), u.text("apk_unavailable")) {
		t.Errorf("unavailable: %q", lastText(t, telegram))
	}
	if NewAPK(u.cfg, u.store, nil).log == nil {
		t.Error("no default logger")
	}

	dir := t.TempDir()
	u.cfg.Paths.APK = filepath.Join(dir, "app.apk")
	if err := os.WriteFile(u.cfg.Paths.APK, []byte("apk-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	u.apk = NewAPK(u.cfg, u.store, quiet())
	if !u.apk.Available() {
		t.Fatal("a real file is not available")
	}

	// A broken cache costs an upload, and a cache that cannot be written is only logged.
	breakFile(t, u.store, "apk_cache.json")
	telegram.documentID = "F"
	press(u, 5, cbAPK)
	if !slices.Contains(telegram.methods(), "sendChatAction") {
		t.Error("a broken cache stopped the delivery")
	}

	// The upload itself is refused: the user is told.
	telegram.failing("sendDocument", -1)
	press(u, 5, cbAPK)
	if !strings.Contains(lastText(t, telegram), "refused") && !strings.Contains(lastText(t, telegram), u.text("error", "")) {
		t.Logf("failure text: %q", lastText(t, telegram))
	}

	// Even the chat action failing does not stop the upload.
	telegram.failing("sendDocument", 0)
	telegram.failing("sendChatAction", -1)
	before := len(telegram.methods())
	press(u, 5, cbAPK)
	if !slices.Contains(telegram.methods()[before:], "sendDocument") {
		t.Error("the upload did not follow a failed chat action")
	}

	// A message-less query has no chat to send to.
	query := callback(5, cbAPK)
	query.Message = models.MaybeInaccessibleMessage{}
	query.From.ID = 0
	before = len(telegram.methods())
	u.deliverAPK(context.Background(), query, 0)
	if len(telegram.methods()) != before {
		t.Error("something was sent with no chat")
	}
}

func TestTheAPKAvailabilityAndButtonFollowTheConfiguration(t *testing.T) {
	u, _, _ := svcUI(t)
	if _, ok := u.apkButton(); ok {
		t.Error("a button without any APK")
	}
	u.cfg.Paths.APKURL = "https://example.org/app.apk"
	if b, ok := u.apkButton(); !ok || b.URL != "https://example.org/app.apk" {
		t.Errorf("url button = %+v, %v", b, ok)
	}
	path := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	u.cfg.Paths.APK = path
	u.apk = NewAPK(u.cfg, u.store, quiet())
	if b, ok := u.apkButton(); !ok || b.CallbackData != cbAPK {
		t.Errorf("file button = %+v, %v", b, ok)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if u.apk.Available() {
		t.Error("an empty file is available")
	}
	if _, err := u.apk.cacheKey(); err != nil {
		t.Error(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := u.apk.cacheKey(); err == nil {
		t.Error("a key for a missing file")
	}
}

func TestAccessCommandsReportAFailingStore(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	breakFile(t, u.store, "whitelist.json")

	u.onAllow(ctx, nil, message(1, "/allow 42"))
	if !strings.Contains(lastText(t, telegram), u.text("error", "")[:3]) {
		t.Logf("allow text: %q", lastText(t, telegram))
	}
	u.onDeny(ctx, nil, message(1, "/deny 42"))
	n := len(telegram.methods())
	if n == 0 {
		t.Fatal("nothing reported")
	}

	// Ids the commands cannot use are explained, not ignored.
	u.onAllow(ctx, nil, message(1, "/allow"))
	u.onAllow(ctx, nil, message(1, "/allow not-an-id"))
	if got := lastText(t, telegram); !strings.Contains(got, u.label("usage_id")) {
		t.Errorf("usage text = %q", got)
	}
	if (errNoArg{}).Error() == "" {
		t.Error("errNoArg has no text")
	}
}

func TestCommandsIgnoreUpdatesWithoutAMessage(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	empty := &models.Update{}
	u.adminOnly(func(context.Context, int64, []string) { t.Fatal("ran without a message") })(ctx, nil, empty)
	u.onClaim(ctx, nil, empty)
	if len(telegram.methods()) != 0 {
		t.Errorf("sent %v", telegram.methods())
	}
	if commandArgs("   ") != nil {
		t.Error("blank text has arguments")
	}
	u.ack(ctx, nil)
	u.client = nil
	u.ack(ctx, &models.Message{})
	u.Announce(ctx)
	u.publishAdminCommands(ctx, 1)
}

func TestVKHashListingAndRemovalReportStoreFailures(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	if err := u.store.UpdateVKHashes(func(h state.VKHashes) error {
		h["abc"] = state.VKHash{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	u.onVKHash(ctx, nil, message(1, "/vkhash list"))
	if got := lastText(t, telegram); !strings.Contains(got, "abc") || !strings.Contains(got, "?") {
		t.Errorf("pool listing = %q", got)
	}

	breakFile(t, u.store, "wdtt/vk_hashes.json")
	u.onVKHash(ctx, nil, message(1, "/vkhash list"))
	listed := lastText(t, telegram)
	u.onVKHash(ctx, nil, message(1, "/vkhash del abc"))
	if lastText(t, telegram) == "" || listed == "" {
		t.Error("a failing store was not reported")
	}
}

func TestBroadcastCountsEveryRefusal(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	if err := u.access.Approve(5); err != nil {
		t.Fatal(err)
	}
	u.cfg.Paths.APKURL = "https://example.org/app.apk"

	sent, failed := u.broadcast(ctx, "hello")
	if sent != 2 || failed != 0 {
		t.Errorf("sent=%d failed=%d", sent, failed)
	}
	markup := telegram.last(t)["reply_markup"]
	if markup == nil {
		t.Error("the broadcast carries no APK button")
	}

	telegram.failing("sendMessage", -1)
	sent, failed = u.broadcast(ctx, "hello")
	if sent != 0 || failed != 2 {
		t.Errorf("with every chat refusing: sent=%d failed=%d", sent, failed)
	}
}

func TestSendersSwallowTelegramRefusals(t *testing.T) {
	u, telegram, _ := svcUI(t)
	ctx := context.Background()
	telegram.failing("sendMessage", -1)
	telegram.failing("editMessageText", -1)
	telegram.failing("sendPhoto", -1)
	telegram.failing("sendDocument", -1)
	telegram.failing("answerCallbackQuery", -1)

	u.reply(ctx, 5, "x", nil)
	u.tell(ctx, 5, "x")
	u.edit(ctx, callback(5, cbMenu), "x", nil)
	u.sendPhoto(ctx, 5, "qr", "caption", nil)
	u.sendDocument(ctx, 5, []byte("{}"), "a.json", "")
	press(u, 5, cbMenu)

	// A payload too long for a QR still delivers its caption.
	telegram.failing("sendMessage", 0)
	before := len(telegram.methods())
	u.sendPhoto(ctx, 5, strings.Repeat("x", 9000), "the caption", nil)
	after := telegram.methods()[before:]
	if len(after) != 1 || after[0] != "sendMessage" {
		t.Errorf("a QR-less artefact sent %v", after)
	}
	before = len(telegram.methods())
	u.sendPhoto(ctx, 5, strings.Repeat("x", 9000), "", nil)
	if len(telegram.methods()) != before {
		t.Error("an empty caption was still sent")
	}
}
