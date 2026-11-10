package naive

import (
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

func TestNaiveUsersAreSwappedWholeAndNeverToNone(t *testing.T) {
	in := &Inbound{logger: log.NewNOPFactory().NewLogger("naive")}
	in.authenticator.Store(auth.NewAuthenticator([]auth.User{{Username: "seed", Password: "old"}}))
	if err := in.ReloadUsers(&option.NaiveInboundOptions{Users: []auth.User{{Username: "alice", Password: "a"}}}); err != nil {
		t.Fatal(err)
	}
	if !in.authenticator.Load().Verify("alice", "a") || in.authenticator.Load().Verify("seed", "old") {
		t.Fatal("the reloaded user list is not the one in force")
	}
	if err := in.ReloadUsers(&option.NaiveInboundOptions{}); err == nil {
		t.Fatal("a reload to no users was accepted")
	}
	if !in.authenticator.Load().Verify("alice", "a") {
		t.Fatal("a refused reload changed the users")
	}
}
