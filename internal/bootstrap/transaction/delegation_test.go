package transaction

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDelegatedDirectoriesAcceptOnlyTheirOwnerAndOnlyInsideTheirTree(t *testing.T) {
	m := &Manager{UID: 0, GID: 0, Delegated: []Delegation{{Root: "/var/lib/x/bot", UID: 993, GID: 984}, {Root: "/srv/relay", UID: 0, GID: 984}}}
	for _, test := range []struct {
		dir      string
		uid, gid uint32
		want     bool
	}{
		{"/var/lib/x/bot", 993, 984, true},
		{"/var/lib/x/bot/wdtt", 993, 984, true},
		{"/var/lib/x/bot", 0, 0, true},
		{"/var/lib/x/bot", 1000, 1000, false},
		{"/var/lib/x/botnet", 993, 984, false},
		{"/var/lib/x", 993, 984, false},
		{"/srv/relay", 0, 984, true},
		{"/srv/relay", 993, 984, false},
	} {
		if got := m.dirOwnerAllowed(test.dir, test.uid, test.gid); got != test.want {
			t.Errorf("dirOwnerAllowed(%s, %d:%d) = %v, want %v", test.dir, test.uid, test.gid, got, test.want)
		}
	}
}

func TestADelegatedDirectoryStillMayNotBeGroupWritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bot")
	if err := os.Mkdir(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	allowAll := func(string, uint32, uint32) bool { return true }
	err := ensureDirOwned(dir, 0o700, uid+1, gid+1, allowAll)
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("err = %v", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirOwned(dir, 0o700, uid+1, gid+1, allowAll); err != nil {
		t.Fatalf("a delegated directory was refused: %v", err)
	}
	if err := ensureDirOwned(dir, 0o700, uid+1, gid+1, nil); err == nil {
		t.Fatal("a directory with another owner was accepted without delegation")
	}
}
