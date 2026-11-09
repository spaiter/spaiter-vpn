package apply

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

func TestADedicatedBotSeesTheManagementEndpointAndNotTheCoresKeys(t *testing.T) {
	h := newHarness(t)
	created := ""
	exists := false
	h.options.LookupUser = func(name string) discover.SystemUser {
		return discover.SystemUser{Name: name, Exists: exists, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	}
	h.options.CreateUser = func(_ context.Context, name string) error {
		created, exists = name, true
		return nil
	}
	h.enableBot(t)
	if !h.options.Desired.Bot.DedicatedUser {
		t.Fatal("new documents should run the bot as its own account")
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if created != "spaiter-vpn-bot" {
		t.Fatalf("created account = %q", created)
	}
	// The account did not exist when the apply began, yet a rollback of it
	// has to write into directories already handed to that account.
	delegated := false
	for _, delegation := range h.options.Manager.Delegated {
		delegated = delegated || delegation.Root == h.layout.BotDataDir()
	}
	if !delegated {
		t.Fatalf("the bot's data directory is not delegated to the account created by this apply: %#v", h.options.Manager.Delegated)
	}
	compose := string(mustRead(t, h.layout.ComposePath()))
	if !strings.Contains(compose, `user: "`) || strings.Contains(compose, ":/sing-box:ro") ||
		!strings.Contains(compose, h.layout.BotManagementPath()+":/etc/spaiter-vpn/management.json:ro") {
		t.Fatalf("the bot service is not isolated:\n%s", compose)
	}
	if !strings.Contains(string(mustRead(t, h.layout.BotConfigPath())), `"management_path": "/etc/spaiter-vpn/management.json"`) {
		t.Fatalf("bot.json does not point at the management file: %s", mustRead(t, h.layout.BotConfigPath()))
	}
	var credentials manage.Credentials
	if err := json.Unmarshal(mustRead(t, h.layout.BotManagementPath()), &credentials); err != nil || credentials.Secret == "" || !strings.HasPrefix(credentials.Controller, "127.0.0.1:") {
		t.Fatalf("management credentials = %#v, %v", credentials, err)
	}
	if info, err := os.Stat(h.layout.BotManagementPath()); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("management file mode = %v, %v", info, err)
	}
	if !strings.Contains(string(mustRead(t, h.layout.PlatformRecordPath())), "spaiter-vpn-bot") {
		t.Fatal("the created account was not recorded")
	}

	// Turning isolation off removes the bot's credentials file again.
	previous := h.options.Desired
	desired := previous
	desired.Bot.DedicatedUser = false
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.layout.BotManagementPath()); !os.IsNotExist(err) {
		t.Fatal("a root bot still has a management credentials file")
	}
	if !strings.Contains(string(mustRead(t, h.layout.ComposePath())), ":/sing-box:ro") {
		t.Fatal("a root bot lost the core's configuration it reads")
	}
}

func TestSwitchingOwnerMovesReceiptOwnedBotStateThroughTheTransaction(t *testing.T) {
	h := newHarness(t)
	h.enableBot(t)
	peer := filepath.Join(h.layout.BotDataDir(), "awg", "42.json")
	if err := os.MkdirAll(filepath.Dir(peer), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(peer, []byte(`{"priv":"a","pub":"b","ip":"10.10.0.9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := transaction.Receipt{Files: map[string]transaction.OwnedFile{
		peer:                   {Ownership: transaction.RuntimeMutable, UID: 0, GID: 0, Mode: 0o600},
		h.layout.ComposePath(): {Ownership: transaction.Managed},
	}}
	owner := fileOwner{uid: 4242, gid: 4242}
	changes, err := h.options.botStateChanges([]transaction.Change{{Path: filepath.Join(h.layout.BotDataDir(), "wdtt", "subs.json"), Data: []byte("{}"), Mode: 0o644}}, receipt, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].UID != 4242 {
		t.Fatalf("changes = %#v", changes)
	}
	moved := changes[1]
	if moved.Path != peer || !moved.ReplaceRuntimeMutable || moved.UID != 4242 || moved.GID != 4242 || string(moved.Data) != `{"priv":"a","pub":"b","ip":"10.10.0.9"}` || moved.ExpectedPriorDigest == "" {
		t.Fatalf("ownership change = %#v", moved)
	}
	// Already at the target owner: nothing to move.
	receipt.Files[peer] = transaction.OwnedFile{Ownership: transaction.RuntimeMutable, UID: 4242, GID: 4242, Mode: 0o600}
	if changes, _ = h.options.botStateChanges(nil, receipt, owner); len(changes) != 0 {
		t.Fatalf("changes for files already owned = %#v", changes)
	}
}

func TestADynamicallyLinkedBotBinaryIsRefused(t *testing.T) {
	// /bin/sh is linked against the C library on every host this runs on;
	// the bot's image has none.
	if err := requireStatic("/bin/sh"); err == nil || !strings.Contains(err.Error(), "dynamically linked") {
		t.Fatalf("err = %v", err)
	}
	script := filepath.Join(t.TempDir(), "spaiter-vpn")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := requireStatic(script); err == nil {
		t.Fatal("a file that is not a binary was accepted")
	}
}
