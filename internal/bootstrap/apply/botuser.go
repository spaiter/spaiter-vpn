package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// fileOwner is who the bot's state files belong to.
type fileOwner struct{ uid, gid uint32 }

// dedicatedBot reports whether the bot runs as its own account.
func (o Options) dedicatedBot() bool {
	return o.Desired.Bot.Enabled && o.Desired.Bot.DedicatedUser
}

// ensureBotUser creates the bot's system account when it is missing and
// returns its ids. Creating an account is not a file transaction: a failed
// apply leaves it, and it is recorded so the operator can see and remove it.
func (o Options) ensureBotUser(ctx context.Context) (fileOwner, error) {
	account := o.lookupUser(deploy.BotUserName)
	if account.Error != "" {
		return fileOwner{}, fmt.Errorf("look up %s: %s", deploy.BotUserName, account.Error)
	}
	if !account.Exists {
		create := o.CreateUser
		if create == nil {
			create = func(ctx context.Context, name string) error {
				out, err := exec.CommandContext(ctx, "useradd", "--system", "--user-group", "--no-create-home",
					"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name).CombinedOutput()
				if err != nil {
					return fmt.Errorf("useradd %s: %w: %s", name, err, strings.TrimSpace(string(out)))
				}
				return nil
			}
		}
		if err := create(ctx, deploy.BotUserName); err != nil {
			return fileOwner{}, err
		}
		if err := recordPlatform(o.Layout.PlatformRecordPath(), "users", map[string]any{
			deploy.BotUserName: map[string]string{"createdAt": time.Now().UTC().Format(time.RFC3339), "purpose": "runs the vpn-bot container"},
		}); err != nil {
			return fileOwner{}, fmt.Errorf("record the created account: %w", err)
		}
		fmt.Fprintf(o.Out, "bot: created system account %s\n", deploy.BotUserName)
		if account = o.lookupUser(deploy.BotUserName); !account.Exists {
			return fileOwner{}, fmt.Errorf("%s does not exist after creating it: %s", deploy.BotUserName, account.Error)
		}
	}
	return fileOwner{uid: account.UID, gid: account.GID}, nil
}

func (o Options) lookupUser(name string) discover.SystemUser {
	if o.LookupUser != nil {
		return o.LookupUser(name)
	}
	return discover.LookupSystemUser(name)
}

// recordPlatform merges one key into platform.json, keeping every other one.
func recordPlatform(path, key string, value map[string]any) error {
	doc := map[string]json.RawMessage{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	merged := map[string]any{}
	if raw, ok := doc[key]; ok {
		_ = json.Unmarshal(raw, &merged)
	}
	for name, entry := range value {
		merged[name] = entry
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	doc[key] = encoded
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// botOwned reports whether a path is bot state: its data directory or the
// relay's passwords file it shares.
func (o Options) botOwned(path string) bool {
	if rel, err := filepath.Rel(o.Layout.BotDataDir(), path); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return true
	}
	return o.Desired.Bot.WDTTConfigDirectory != "" && path == filepath.Join(o.Desired.Bot.WDTTConfigDirectory, "passwords.json")
}

// botStateChanges gives every bot-state change the bot's owner, and adds the
// changes that move receipt-owned bot files to that owner when it differs from
// what the receipt recorded: switching the bot to or from its account.
func (o Options) botStateChanges(changes []transaction.Change, receipt transaction.Receipt, owner fileOwner) ([]transaction.Change, error) {
	present := map[string]bool{}
	for i := range changes {
		present[changes[i].Path] = true
		if o.botOwned(changes[i].Path) && !changes[i].Delete {
			changes[i].UID, changes[i].GID = owner.uid, owner.gid
		}
	}
	for path, owned := range receipt.Files {
		if present[path] || !o.botOwned(path) || owned.Ownership != transaction.RuntimeMutable {
			continue
		}
		if owned.UID == owner.uid && owned.GID == owner.gid {
			continue
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("bot state %s is not a regular file", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		changes = append(changes, transaction.Change{
			Path: path, Data: data, Mode: info.Mode().Perm(), UID: owner.uid, GID: owner.gid,
			Ownership: transaction.RuntimeMutable, ReplaceRuntimeMutable: true, ExpectedPriorDigest: digestOf(data),
		})
	}
	return changes, nil
}

// chownBotState hands everything else in the bot's data directory to its
// owner, and lets it write the relay directory it shares. Files the receipt
// owns moved through the transaction; these are the ones the bot created
// itself. Not undone by a rollback: an earlier owner reading them again needs
// nothing, because the previous bot ran as root.
func (o Options) chownBotState(owned map[string]bool, owner fileOwner) error {
	root := o.Layout.BotDataDir()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if owned[path] && !entry.IsDir() {
			return nil
		}
		return os.Lchown(path, int(owner.uid), int(owner.gid))
	})
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("hand the bot's data to its account: %w", err)
	}
	if dir := o.Desired.Bot.WDTTConfigDirectory; dir != "" {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		// Enterable by the bot's group, writable by nobody but root: bootstrap's
		// own transactions refuse a group-writable directory. The bot owns
		// passwords.json and rewrites it in place instead of by rename.
		if err := os.Chown(dir, -1, int(owner.gid)); err != nil {
			return err
		}
		if err := os.Chmod(dir, info.Mode().Perm()&^0o022|0o050); err != nil {
			return err
		}
		passwords := filepath.Join(dir, "passwords.json")
		if !owned[passwords] {
			if err := os.Lchown(passwords, int(owner.uid), int(owner.gid)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

// managementChange is the bot's view of the core: the management endpoint and
// secret, readable by the bot's group. A bot that is not isolated reads the
// core's configuration as before, and an earlier file is removed.
func (o Options) managementChange(manager *transaction.Manager, receipt transaction.Receipt, coreConfig []byte, owner fileOwner) ([]transaction.Change, error) {
	path := o.Layout.BotManagementPath()
	if !o.dedicatedBot() {
		if _, owned := receipt.Files[path]; owned {
			return []transaction.Change{{Path: path, Delete: true, Ownership: transaction.Managed}}, nil
		}
		return nil, nil
	}
	credentials, err := manage.CredentialsFromCoreConfig(coreConfig)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return nil, err
	}
	return []transaction.Change{{Path: path, Data: append(data, '\n'), Mode: 0o640, UID: manager.UID, GID: owner.gid, Ownership: transaction.Managed}}, nil
}

// serviceAccounts are the group and web account bootstrap created or found.
// Zero means not needed.
type serviceAccounts struct {
	gid    uint32
	webUID uint32
}

// ensureServiceAccounts creates the service group the control socket and the
// web UI's key belong to, and the web UI's own account, when the desired
// state runs something that needs them. Like the bot's account, they are
// recorded and never removed automatically.
func (o Options) ensureServiceAccounts(ctx context.Context) (serviceAccounts, error) {
	var out serviceAccounts
	needGroup := o.Desired.Bootstrap.ManageControl && (o.dedicatedBot() || o.Desired.Bootstrap.ManageWeb)
	if !needGroup {
		return out, nil
	}
	run := o.RunAccountCommand
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) error {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	gid, found, err := o.lookupGroup(deploy.ServiceGroup)
	if err != nil {
		return out, err
	}
	if !found {
		if err := run(ctx, "groupadd", "--system", deploy.ServiceGroup); err != nil {
			return out, err
		}
		if err := recordPlatform(o.Layout.PlatformRecordPath(), "groups", map[string]any{
			deploy.ServiceGroup: map[string]string{"createdAt": time.Now().UTC().Format(time.RFC3339), "purpose": "may use the control socket and read the web UI's key"},
		}); err != nil {
			return out, err
		}
		if gid, found, err = o.lookupGroup(deploy.ServiceGroup); err != nil || !found {
			return out, fmt.Errorf("%s does not exist after creating it: %v", deploy.ServiceGroup, err)
		}
	}
	out.gid = gid
	if !o.Desired.Bootstrap.ManageWeb {
		return out, nil
	}
	account := o.lookupUser(deploy.WebUserName)
	if account.Error != "" {
		return out, fmt.Errorf("look up %s: %s", deploy.WebUserName, account.Error)
	}
	if !account.Exists {
		if err := run(ctx, "useradd", "--system", "--gid", deploy.ServiceGroup, "--no-create-home",
			"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", deploy.WebUserName); err != nil {
			return out, err
		}
		if err := recordPlatform(o.Layout.PlatformRecordPath(), "users", map[string]any{
			deploy.WebUserName: map[string]string{"createdAt": time.Now().UTC().Format(time.RFC3339), "purpose": "runs the web UI"},
		}); err != nil {
			return out, err
		}
		if account = o.lookupUser(deploy.WebUserName); !account.Exists {
			return out, fmt.Errorf("%s does not exist after creating it: %s", deploy.WebUserName, account.Error)
		}
	}
	out.webUID = account.UID
	return out, nil
}

func (o Options) lookupGroup(name string) (uint32, bool, error) {
	if o.LookupGroup != nil {
		return o.LookupGroup(name)
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return 0, false, nil
		}
		return 0, false, err
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 {
		return 0, false, fmt.Errorf("group %s has gid %s, not an unprivileged numeric group", name, group.Gid)
	}
	return uint32(gid), true, nil
}
