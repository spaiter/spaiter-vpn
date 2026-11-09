package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/control"
)

// Server administration goes through the local control daemon, never through
// Docker or a shell: the bot asks for a typed change, shows the admin the plan
// the daemon computed, and commits only the ticket the admin confirmed. The
// daemon recomputes that plan under its own lock and refuses if the host moved.

// Control is the part of control.Client the bot uses.
type Control interface {
	Do(ctx context.Context, request control.Request) (control.Response, error)
}

// SetControl attaches the control daemon. Without one the server menu is
// absent and its commands say so.
func (u *UI) SetControl(c Control) { u.control = c }

const (
	cbServer   = "a:srv"
	cbGens     = "a:gens"
	cbRollback = "a:rb"
	cbConfirm  = "a:ok:"
	cbAbort    = "a:no:"
)

func isServerCallback(data string) bool {
	return data == cbServer || data == cbGens || data == cbRollback ||
		strings.HasPrefix(data, cbConfirm) || strings.HasPrefix(data, cbAbort)
}

func (u *UI) serverRows() [][]models.InlineKeyboardButton {
	if u.control == nil {
		return nil
	}
	return [][]models.InlineKeyboardButton{row(button(u.label("a:srv"), cbServer))}
}

// handleServer routes the server menu's buttons. The caller is an admin; the
// router has checked.
func (u *UI) handleServer(ctx context.Context, query *models.CallbackQuery, uid int64, data string) {
	if u.control == nil {
		u.edit(ctx, query, u.text("srv_unavailable"), u.backKeyboard())
		return
	}
	switch {
	case data == cbServer:
		response, err := u.control.Do(ctx, control.Request{Operation: control.OpStatus})
		if err != nil || !response.OK {
			u.edit(ctx, query, u.text("srv_failed", controlError(response, err)), u.backKeyboard())
			return
		}
		u.edit(ctx, query, u.text("srv_status", codeBlock(renderStatus(response.Result))), u.serverKeyboard())
	case data == cbGens:
		response, err := u.control.Do(ctx, control.Request{Operation: control.OpGenerations})
		if err != nil || !response.OK {
			u.edit(ctx, query, u.text("srv_failed", controlError(response, err)), u.backKeyboard())
			return
		}
		u.edit(ctx, query, u.text("srv_generations", codeBlock(renderGenerations(response.Result))), u.serverKeyboard())
	case data == cbRollback:
		u.prepare(ctx, uid, control.Change{Kind: control.ChangeRollback})
	case strings.HasPrefix(data, cbConfirm):
		ticket := strings.TrimPrefix(data, cbConfirm)
		u.edit(ctx, query, u.text("srv_applying"), nil)
		response, err := u.control.Do(ctx, control.Request{Operation: control.OpCommit, Ticket: ticket})
		if err != nil || !response.OK {
			u.edit(ctx, query, u.text("srv_failed", controlError(response, err)), u.backKeyboard())
			return
		}
		var result struct {
			Transaction string `json:"Transaction"`
		}
		_ = json.Unmarshal(response.Result, &result)
		u.edit(ctx, query, u.text("srv_applied", result.Transaction), u.backKeyboard())
	case strings.HasPrefix(data, cbAbort):
		_, _ = u.control.Do(ctx, control.Request{Operation: control.OpCancel, Ticket: strings.TrimPrefix(data, cbAbort)})
		u.edit(ctx, query, u.text("srv_cancelled"), u.backKeyboard())
	default:
		u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
	}
}

func (u *UI) serverKeyboard() *models.InlineKeyboardMarkup {
	return keyboard(
		row(button(u.label("a:gens"), cbGens), button(u.label("a:rb"), cbRollback)),
		row(button(u.label("menu"), cbMenu)),
	)
}

// prepare asks the daemon to plan a change and shows the plan with the two
// buttons that decide it. Nothing has changed on the host yet.
func (u *UI) prepare(ctx context.Context, uid int64, change control.Change) {
	if u.control == nil {
		u.reply(ctx, uid, u.text("srv_unavailable"), nil)
		return
	}
	if err := change.Validate(); err != nil {
		u.reply(ctx, uid, u.text("srv_failed", err.Error()), nil)
		return
	}
	response, err := u.control.Do(ctx, control.Request{Operation: control.OpPrepare, Change: &change})
	if err != nil || !response.OK {
		u.reply(ctx, uid, u.text("srv_failed", controlError(response, err)), nil)
		return
	}
	var ticket struct {
		ID   string          `json:"id"`
		Plan json.RawMessage `json:"plan"`
	}
	if err := json.Unmarshal(response.Result, &ticket); err != nil || ticket.ID == "" {
		u.reply(ctx, uid, u.text("srv_failed", "the daemon returned no ticket"), nil)
		return
	}
	u.reply(ctx, uid, u.text("srv_plan", change.Summary(), codeBlock(renderPlan(ticket.Plan))), keyboard(row(
		styled(button(u.label("srv_apply"), cbConfirm+ticket.ID), styleSuccess),
		styled(button(u.label("srv_cancel"), cbAbort+ticket.ID), styleDanger),
	)))
}

// SetWebLogin attaches what mints a web UI login link.
func (u *UI) SetWebLogin(mint func() (string, error)) { u.webLogin = mint }

// onWebLogin sends an admin a one-time link to the web UI, privately.
func (u *UI) onWebLogin(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, _ []string) {
		if u.webLogin == nil {
			u.reply(ctx, uid, u.text("web_unavailable"), nil)
			return
		}
		link, err := u.webLogin()
		if err != nil {
			u.reply(ctx, uid, u.text("srv_failed", err.Error()), nil)
			return
		}
		u.reply(ctx, uid, u.text("web_link", link), nil)
	})(ctx, client, update)
}

func (u *UI) onRotate(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		if len(args) == 0 {
			u.reply(ctx, uid, u.label("usage_rotate"), nil)
			return
		}
		u.prepare(ctx, uid, control.Change{Kind: control.ChangeRotate, Users: args})
	})(ctx, client, update)
}

func (u *UI) onPort(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		port, err := strconv.ParseUint(argAt(args, 1), 10, 16)
		if len(args) != 2 || err != nil || port == 0 {
			u.reply(ctx, uid, u.label("usage_port"), nil)
			return
		}
		u.prepare(ctx, uid, control.Change{Kind: control.ChangeSettings, Ports: map[string]uint16{args[0]: uint16(port)}})
	})(ctx, client, update)
}

func (u *UI) onImage(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		if len(args) != 1 {
			u.reply(ctx, uid, u.label("usage_image"), nil)
			return
		}
		u.prepare(ctx, uid, control.Change{Kind: control.ChangeImage, Image: args[0]})
	})(ctx, client, update)
}

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func controlError(response control.Response, err error) string {
	if err != nil {
		return err.Error()
	}
	return response.Error
}

// codeBlock keeps Markdown V1 away from planner text, which is full of
// underscores and asterisks it would otherwise try to format.
func codeBlock(text string) string {
	return "```\n" + strings.ReplaceAll(text, "```", "'''") + "\n```"
}

func clip(text string, limit int) string {
	if len([]rune(text)) <= limit {
		return text
	}
	return string([]rune(text)[:limit-1]) + "…"
}

func renderStatus(raw json.RawMessage) string {
	var status struct {
		Tier          string `json:"tier"`
		Image         string `json:"image"`
		SeedUsers     int    `json:"seedUsers"`
		Generation    uint64 `json:"generation"`
		Transaction   string `json:"transaction"`
		ServicesError string `json:"servicesError"`
		Services      []struct {
			Service string `json:"Service"`
			State   string `json:"State"`
			Health  string `json:"Health"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return string(raw)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "generation %d (%s)\ntier %s, %d seed users\nimage %s\n", status.Generation, status.Transaction, status.Tier, status.SeedUsers, clip(status.Image, 60))
	for _, service := range status.Services {
		fmt.Fprintf(&b, "%-12s %s %s\n", service.Service, service.State, service.Health)
	}
	if status.ServicesError != "" {
		fmt.Fprintf(&b, "services: %s\n", clip(status.ServicesError, 120))
	}
	return strings.TrimSpace(b.String())
}

func renderGenerations(raw json.RawMessage) string {
	var generations []struct {
		Sequence    uint64 `json:"Sequence"`
		CommittedAt string `json:"CommittedAt"`
	}
	if err := json.Unmarshal(raw, &generations); err != nil {
		return string(raw)
	}
	var b strings.Builder
	for _, generation := range generations {
		fmt.Fprintf(&b, "%3d  %s\n", generation.Sequence, clip(generation.CommittedAt, 19))
	}
	return strings.TrimSpace(b.String())
}

// renderPlan shows what the admin is consenting to: the mode, each desired
// state change and each action that changes the host.
func renderPlan(raw json.RawMessage) string {
	var p struct {
		Mode    string `json:"mode"`
		Changes []struct {
			Path   string `json:"path"`
			Before any    `json:"before"`
			After  any    `json:"after"`
		} `json:"changes"`
		Actions []struct {
			Mutates bool   `json:"mutates"`
			Summary string `json:"summary"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "unreadable plan"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "mode: %s\n", p.Mode)
	for _, change := range p.Changes {
		before, _ := json.Marshal(change.Before)
		after, _ := json.Marshal(change.After)
		fmt.Fprintf(&b, "%s: %s -> %s\n", change.Path, clip(string(before), 40), clip(string(after), 40))
	}
	shown := 0
	for _, action := range p.Actions {
		if !action.Mutates {
			continue
		}
		if shown == 12 {
			b.WriteString("…\n")
			break
		}
		fmt.Fprintf(&b, "* %s\n", clip(action.Summary, 90))
		shown++
	}
	return strings.TrimSpace(b.String())
}
