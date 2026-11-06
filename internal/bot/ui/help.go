package ui

import (
	"context"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// /help is a rich message (Bot API 10.1+): headings, a numbered walkthrough, a
// table of commands and a button block, rendered by the client as a page
// rather than as a wall of Markdown. Where the client or the API server cannot
// show one, the old greeting with the menu goes out instead -- the content a
// user needs to get a configuration is the same either way.

// onHelp answers /help.
func (u *UI) onHelp(ctx context.Context, client *bot.Bot, update *models.Update) {
	if update.Message == nil {
		return
	}
	uid := u.caller(update.Message.From)
	if !u.access.IsAllowed(uid) {
		// Same path as /start: there is nothing to explain to someone who is
		// not in yet except how to get in.
		u.onStart(ctx, client, update)
		return
	}
	if _, err := u.client.SendRichMessage(ctx, &bot.SendRichMessageParams{
		ChatID:      uid,
		RichMessage: u.helpMessage(u.access.IsAdmin(uid)),
	}); err != nil {
		u.log.Info("rich help was refused, sending the plain one", "error", err)
		u.reply(ctx, uid, u.cfg.UI.Hello, u.mainMenu(uid))
		return
	}
	u.ack(ctx, update.Message)
}

// helpMessage builds the help page for one kind of caller.
func (u *UI) helpMessage(admin bool) models.InputRichMessage {
	h := u.cfg.UI.Help
	blocks := []models.InputRichBlock{
		heading(h["title"], 1),
		paragraph(plain(h["intro"])),
		heading(h["steps_title"], 2),
		numbered(splitLines(h["steps"])...),
		heading(h["commands_title"], 2),
		u.commandTable(userCommands),
	}
	if admin {
		blocks = append(blocks,
			details(h["admin_title"], u.commandTable(adminCommands), paragraph(plain(h["admin_hint"]))),
		)
	}
	if footer := h["footer"]; footer != "" {
		blocks = append(blocks, divider(), paragraph(plain(footer)))
	}
	blocks = append(blocks, buttons(
		models.RichMessageButton{Text: plain(u.label("open_menu")), CallbackData: cbMenuNew, Style: stylePrimary},
		models.RichMessageButton{Text: plain(u.label("allsub")), CallbackData: cbAllMethods},
	))
	return models.InputRichMessage{Blocks: blocks, SkipEntityDetection: true}
}

// commandTable lists commands with what they do.
func (u *UI) commandTable(names []string) models.InputRichBlock {
	cells := [][]models.RichBlockTableCell{{
		{Text: ptr(bold(u.label("col_command"))), IsHeader: true},
		{Text: ptr(bold(u.label("col_action"))), IsHeader: true},
	}}
	for _, name := range names {
		desc := u.cfg.UI.Commands[name]
		if desc == "" {
			continue
		}
		cells = append(cells, []models.RichBlockTableCell{
			{Text: ptr(code("/" + name))},
			{Text: ptr(plain(desc))},
		})
	}
	return models.InputRichBlock{
		Type: models.RichBlockTypeTable,
		InputRichBlockTable: &models.InputRichBlockTable{
			Cells: cells, IsBordered: true, IsCompact: true,
		},
	}
}

// --- rich text and block constructors ---

func plain(s string) models.RichText { return models.RichText{PlainText: s} }

func bold(s string) models.RichText {
	return models.RichText{Type: models.RichTextTypeBold, RichTextBold: &models.RichTextBold{Text: plain(s)}}
}

func code(s string) models.RichText {
	return models.RichText{Type: models.RichTextTypeCode, RichTextCode: &models.RichTextCode{Text: plain(s)}}
}

func ptr(t models.RichText) *models.RichText { return &t }

func heading(text string, size int) models.InputRichBlock {
	return models.InputRichBlock{
		Type:                         models.RichBlockTypeSectionHeading,
		InputRichBlockSectionHeading: &models.InputRichBlockSectionHeading{Text: plain(text), Size: size},
	}
}

func paragraph(text models.RichText) models.InputRichBlock {
	return models.InputRichBlock{
		Type:                    models.RichBlockTypeParagraph,
		InputRichBlockParagraph: &models.InputRichBlockParagraph{Text: text},
	}
}

func divider() models.InputRichBlock {
	return models.InputRichBlock{Type: models.RichBlockTypeDivider, InputRichBlockDivider: &models.InputRichBlockDivider{}}
}

// numbered is an ordered list of one paragraph per item.
func numbered(items ...string) models.InputRichBlock {
	list := &models.InputRichBlockList{}
	for i, item := range items {
		list.Items = append(list.Items, models.InputRichBlockListItem{
			Type:   "numbered",
			Value:  i + 1,
			Blocks: []models.InputRichBlock{paragraph(plain(item))},
		})
	}
	return models.InputRichBlock{Type: models.RichBlockTypeList, InputRichBlockList: list}
}

func details(summary string, inner ...models.InputRichBlock) models.InputRichBlock {
	return models.InputRichBlock{
		Type:                  models.RichBlockTypeDetails,
		InputRichBlockDetails: &models.InputRichBlockDetails{Summary: bold(summary), Blocks: inner},
	}
}

func buttons(b ...models.RichMessageButton) models.InputRichBlock {
	return models.InputRichBlock{
		Type:                  models.RichBlockTypeButtons,
		InputRichBlockButtons: &models.InputRichBlockButtons{Buttons: b},
	}
}

// splitLines turns a newline-separated config value into items, dropping
// blanks so a trailing newline is not an empty step.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
