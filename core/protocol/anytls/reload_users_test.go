package anytls

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

// apply hands over what the inbound registry built, and that is a POINTER to
// the options struct. Accepting only the value shape makes every reload fail
// and silently degrade into recreating the inbound.
func TestReloadUsersRequiresPointerOptions(t *testing.T) {
	h := &Inbound{}
	if err := h.ReloadUsers(option.AnyTLSInboundOptions{}); err == nil {
		t.Fatal("value options are not what the registry produces; must be rejected")
	}
	if err := h.ReloadUsers("nonsense"); err == nil {
		t.Fatal("unrelated type must be rejected")
	}
}
