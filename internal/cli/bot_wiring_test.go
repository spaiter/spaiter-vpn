package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
)

func TestBuiltBotRendersItsNotificationsFromTheConfiguredTexts(t *testing.T) {
	controller, _ := fakeCore(t)
	_, cfg := botFiles(t, controller, func(c *botcfg.Config) {
		c.UI.Buttons["change_default_reason"] = "a default reason"
		c.UI.Messages["subscription_changed"] = "changed: %s"
		c.UI.Messages["vk_pool_dead"] = "dead: %s"
		c.UI.Messages["vk_link_died"] = "your link died"
		c.UI.Messages["vk_pool_low"] = "low: %d"
		c.Paths.ControlSocket = "/run/spaiter-vpn/control.sock"
	})
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}

	if got := parts.refresher.ChangedText(""); got != "changed: a default reason" {
		t.Errorf("default reason: %q", got)
	}
	if got := parts.refresher.ChangedText("a new port"); got != "changed: a new port" {
		t.Errorf("explicit reason: %q", got)
	}
	if got := parts.pool.DeadText([]string{"h1", "h2"}); !strings.HasPrefix(got, "dead: ") || !strings.Contains(got, "h1") {
		t.Errorf("dead pool: %q", got)
	}
	if got := parts.pool.OwnerText("h1"); got != "your link died" {
		t.Errorf("owner: %q", got)
	}
	if got := parts.pool.LowPoolText(2); got != "low: 2" {
		t.Errorf("low pool: %q", got)
	}
}

func TestTheBackgroundLoopsCanOnlyReadBundles(t *testing.T) {
	controller, _ := fakeCore(t)
	_, cfg := botFiles(t, controller, nil)
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	bundles := readOnlyBundles{parts.svc}
	raw, err := bundles.Bundle(context.Background(), "42")
	if err == nil && !json.Valid(raw) {
		t.Errorf("a bundle that is not JSON: %q", raw)
	}
	// Whatever the answer, nothing was created for a user who asked for nothing.
	if _, found, _ := parts.store.Peer("42", "awg-in"); found {
		t.Error("a background read provisioned a peer")
	}
}
