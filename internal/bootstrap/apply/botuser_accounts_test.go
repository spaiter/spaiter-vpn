package apply

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
)

func accountOptions(t *testing.T) Options {
	t.Helper()
	var desired state.State
	desired.Bot.Enabled, desired.Bot.DedicatedUser = true, true
	desired.Bootstrap.ManageControl, desired.Bootstrap.ManageWeb = true, true
	return Options{
		Layout:  discover.Layout{DataRoot: t.TempDir()},
		Desired: desired,
		Out:     &bytes.Buffer{},
	}
}

func TestBotUserCreationFailuresAreReportedAndLeaveNoRecord(t *testing.T) {
	o := accountOptions(t)

	o.LookupUser = func(string) discover.SystemUser { return discover.SystemUser{Error: "nss down"} }
	if _, err := o.ensureBotUser(context.Background()); err == nil || !strings.Contains(err.Error(), "nss down") {
		t.Errorf("lookup failure: %v", err)
	}

	o.LookupUser = func(string) discover.SystemUser { return discover.SystemUser{} }
	o.CreateUser = func(context.Context, string) error { return errors.New("useradd refused") }
	if _, err := o.ensureBotUser(context.Background()); err == nil || !strings.Contains(err.Error(), "useradd refused") {
		t.Errorf("create failure: %v", err)
	}
	if _, err := os.Stat(o.Layout.PlatformRecordPath()); !os.IsNotExist(err) {
		t.Error("a failed creation was recorded")
	}

	// Created, yet still absent afterwards.
	o.CreateUser = func(context.Context, string) error { return nil }
	if _, err := o.ensureBotUser(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist after creating") {
		t.Errorf("vanished account: %v", err)
	}

	// An unwritable record directory fails the apply rather than hiding it.
	blocker := o.Layout.BootstrapStateDir()
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ensureBotUser(context.Background()); err == nil || !strings.Contains(err.Error(), "record the created account") {
		t.Errorf("record failure: %v", err)
	}
}

func TestAnExistingBotUserIsReturnedWithoutCreatingAnything(t *testing.T) {
	o := accountOptions(t)
	o.LookupUser = func(name string) discover.SystemUser {
		return discover.SystemUser{Name: name, Exists: true, UID: 901, GID: 902}
	}
	o.CreateUser = func(context.Context, string) error { t.Fatal("created an account that exists"); return nil }
	owner, err := o.ensureBotUser(context.Background())
	if err != nil || owner != (fileOwner{uid: 901, gid: 902}) {
		t.Errorf("owner = %+v, err = %v", owner, err)
	}
}

func TestTheDefaultAccountCreatorRunsUseraddAndReportsItsOutput(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"$@\" >" + dir + "/args\necho nope >&2\nexit 9\n"
	if err := os.WriteFile(dir+"/useradd", []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	o := accountOptions(t)
	o.LookupUser = func(string) discover.SystemUser { return discover.SystemUser{} }
	_, err := o.ensureBotUser(context.Background())
	if err == nil || !strings.Contains(err.Error(), "useradd "+deploy.BotUserName) || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v", err)
	}
	args, _ := os.ReadFile(dir + "/args")
	if !strings.Contains(string(args), "--system") || !strings.Contains(string(args), "/usr/sbin/nologin") {
		t.Errorf("useradd was called with %q", args)
	}
}

type accountWorld struct {
	groups   map[string]uint32
	users    map[string]discover.SystemUser
	commands []string
}

func (w *accountWorld) options(o Options) Options {
	o.LookupGroup = func(name string) (uint32, bool, error) {
		gid, ok := w.groups[name]
		return gid, ok, nil
	}
	o.LookupUser = func(name string) discover.SystemUser {
		if u, ok := w.users[name]; ok {
			return u
		}
		return discover.SystemUser{}
	}
	o.RunAccountCommand = func(_ context.Context, name string, args ...string) error {
		w.commands = append(w.commands, name+" "+strings.Join(args, " "))
		switch name {
		case "groupadd":
			w.groups[deploy.ServiceGroup] = 700
		case "useradd":
			w.users[deploy.WebUserName] = discover.SystemUser{Name: deploy.WebUserName, Exists: true, UID: 701, GID: 700}
		}
		return nil
	}
	return o
}

func TestServiceAccountsAreCreatedOnceAndRecorded(t *testing.T) {
	world := &accountWorld{groups: map[string]uint32{}, users: map[string]discover.SystemUser{}}
	o := world.options(accountOptions(t))

	got, err := o.ensureServiceAccounts(context.Background())
	if err != nil || got != (serviceAccounts{gid: 700, webUID: 701}) {
		t.Fatalf("accounts = %+v, err = %v", got, err)
	}
	if len(world.commands) != 2 || !strings.HasPrefix(world.commands[0], "groupadd --system") ||
		!strings.Contains(world.commands[1], "--gid "+deploy.ServiceGroup) {
		t.Errorf("commands = %q", world.commands)
	}
	record, _ := os.ReadFile(o.Layout.PlatformRecordPath())
	if !strings.Contains(string(record), deploy.ServiceGroup) || !strings.Contains(string(record), deploy.WebUserName) {
		t.Errorf("platform record = %s", record)
	}

	// A second run finds both and changes nothing.
	world.commands = nil
	if again, err := o.ensureServiceAccounts(context.Background()); err != nil || again != got || len(world.commands) != 0 {
		t.Errorf("second run: %+v, %v, %q", again, err, world.commands)
	}
}

func TestServiceAccountsAreSkippedOrReducedWhenNotNeeded(t *testing.T) {
	world := &accountWorld{groups: map[string]uint32{}, users: map[string]discover.SystemUser{}}

	off := accountOptions(t)
	off.Desired.Bootstrap.ManageControl = false
	if got, err := world.options(off).ensureServiceAccounts(context.Background()); err != nil || got != (serviceAccounts{}) || len(world.commands) != 0 {
		t.Errorf("without the control daemon: %+v, %v, %q", got, err, world.commands)
	}

	groupOnly := accountOptions(t)
	groupOnly.Desired.Bootstrap.ManageWeb = false
	got, err := world.options(groupOnly).ensureServiceAccounts(context.Background())
	if err != nil || got != (serviceAccounts{gid: 700}) || len(world.commands) != 1 {
		t.Errorf("group only: %+v, %v, %q", got, err, world.commands)
	}
}

func TestServiceAccountFailuresStopTheApply(t *testing.T) {
	boom := errors.New("boom")
	fresh := func() (*accountWorld, Options) {
		w := &accountWorld{groups: map[string]uint32{}, users: map[string]discover.SystemUser{}}
		return w, w.options(accountOptions(t))
	}

	_, o := fresh()
	o.LookupGroup = func(string) (uint32, bool, error) { return 0, false, boom }
	if _, err := o.ensureServiceAccounts(context.Background()); !errors.Is(err, boom) {
		t.Errorf("group lookup: %v", err)
	}

	_, o = fresh()
	o.RunAccountCommand = func(context.Context, string, ...string) error { return boom }
	if _, err := o.ensureServiceAccounts(context.Background()); !errors.Is(err, boom) {
		t.Errorf("groupadd: %v", err)
	}

	// The group "was created" but cannot be found afterwards.
	_, o = fresh()
	o.RunAccountCommand = func(context.Context, string, ...string) error { return nil }
	if _, err := o.ensureServiceAccounts(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist after creating") {
		t.Errorf("vanished group: %v", err)
	}

	w, o := fresh()
	w.groups[deploy.ServiceGroup] = 700
	o.LookupUser = func(string) discover.SystemUser { return discover.SystemUser{Error: "nss down"} }
	if _, err := o.ensureServiceAccounts(context.Background()); err == nil || !strings.Contains(err.Error(), "nss down") {
		t.Errorf("web user lookup: %v", err)
	}

	w, o = fresh()
	w.groups[deploy.ServiceGroup] = 700
	inner := o.RunAccountCommand
	o.RunAccountCommand = func(ctx context.Context, name string, args ...string) error {
		if name == "useradd" {
			return boom
		}
		return inner(ctx, name, args...)
	}
	if _, err := o.ensureServiceAccounts(context.Background()); !errors.Is(err, boom) {
		t.Errorf("useradd: %v", err)
	}

	// useradd "succeeds" yet the account is not there.
	w, o = fresh()
	w.groups[deploy.ServiceGroup] = 700
	o.RunAccountCommand = func(context.Context, string, ...string) error { return nil }
	if _, err := o.ensureServiceAccounts(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist after creating") {
		t.Errorf("vanished web user: %v", err)
	}
}

func TestTheDefaultAccountCommandRunnerReportsFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/groupadd", []byte("#!/bin/sh\necho denied\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	o := accountOptions(t)
	o.LookupGroup = func(string) (uint32, bool, error) { return 0, false, nil }
	_, err := o.ensureServiceAccounts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "groupadd --system") || !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v", err)
	}
}

func TestTheSystemGroupDatabaseIsReadWithoutAcceptingRoot(t *testing.T) {
	o := Options{}
	if _, found, err := o.lookupGroup("spaiter-no-such-group-xyz"); err != nil || found {
		t.Errorf("unknown group: found=%v err=%v", found, err)
	}
	// root's group is gid 0, which a service account must never be.
	if _, found, err := o.lookupGroup("root"); err == nil || found {
		t.Errorf("root group accepted: found=%v err=%v", found, err)
	}
}
