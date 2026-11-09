package ui

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/bot/telegram"
)

// APK hands out the Android client build.
//
// Uploaded once and then re-sent by the id Telegram gives back, because the
// build is tens of megabytes and every user would otherwise pay the upload
// again. The cache is keyed by size and modification time, so a fresh build
// re-uploads by itself and a stale id is never handed out -- that is the whole
// reason the key is not just the path.
type APK struct {
	cfg   botcfg.Config
	store *state.Store
	log   *slog.Logger
}

// NewAPK builds the handler.
func NewAPK(cfg botcfg.Config, store *state.Store, log *slog.Logger) *APK {
	if log == nil {
		log = slog.Default()
	}
	return &APK{cfg: cfg, store: store, log: log}
}

// Available reports whether there is a file to send.
func (a *APK) Available() bool {
	if a.cfg.Paths.APK == "" {
		return false
	}
	info, err := os.Stat(a.cfg.Paths.APK)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// cacheKey identifies this exact build.
func (a *APK) cacheKey() (string, error) {
	info, err := os.Stat(a.cfg.Paths.APK)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%d", info.Size(), info.ModTime().Unix()), nil
}

// deliverAPK sends the Android build to a user.
func (u *UI) deliverAPK(ctx context.Context, query *models.CallbackQuery, uid int64) {
	chat := queryChat(query)
	if chat == 0 {
		return
	}
	if !u.apk.Available() {
		u.reply(ctx, chat, u.text("apk_unavailable"), u.backKeyboard())
		return
	}

	key, err := u.apk.cacheKey()
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	cache, err := u.store.APKCache()
	if err != nil {
		// A broken cache costs an upload, not the delivery.
		u.log.Warn("could not read the APK cache", "error", err)
		cache = state.APKCache{}
	}

	caption := u.text("caption_apk", u.cfg.Paths.APKVersion)
	// One entry, not a map: a key that does not match means the file on disk
	// is a different build, and the id for the old one is worthless.
	if cache.Key == key && cache.FileID != "" {
		if _, err := u.client.SendDocument(ctx, &bot.SendDocumentParams{
			ChatID:    chat,
			Document:  &models.InputFileString{Data: cache.FileID},
			Caption:   caption,
			ParseMode: telegram.DefaultParseMode,
		}); err == nil {
			return
		}
		// Telegram forgets a file id eventually, and it does so silently. Fall
		// through to a fresh upload rather than telling the user it is broken.
		u.log.Info("the cached APK id was refused; uploading again")
	}

	// Chat action first: a large upload takes long enough that the chat looks
	// idle without it.
	if _, err := u.client.SendChatAction(ctx, &bot.SendChatActionParams{
		ChatID: chat, Action: models.ChatActionUploadDocument,
	}); err != nil {
		u.log.Debug("could not set a chat action", "error", err)
	}

	file, err := os.Open(u.cfg.Paths.APK)
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	defer file.Close()

	message, err := u.client.SendDocument(ctx, &bot.SendDocumentParams{
		ChatID:    chat,
		Document:  &models.InputFileUpload{Filename: apkFilename(u.cfg), Data: file},
		Caption:   caption,
		ParseMode: telegram.DefaultParseMode,
	})
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	if message.Document == nil || message.Document.FileID == "" {
		return
	}

	if err := u.store.SetAPKCache(state.APKCache{
		Key: key, FileID: message.Document.FileID,
	}); err != nil {
		u.log.Warn("could not record the APK id; the next user will re-upload", "error", err)
	}
}

// apkFilename names the download, with the version in it so a user can tell
// two builds apart in their downloads folder.
func apkFilename(cfg botcfg.Config) string {
	if cfg.Paths.APKVersion == "" {
		return "client.apk"
	}
	return "client-" + cfg.Paths.APKVersion + ".apk"
}
