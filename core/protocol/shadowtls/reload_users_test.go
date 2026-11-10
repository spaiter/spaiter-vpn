package shadowtls

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestReloadUsersRequiresPointerOptions(t *testing.T) {
	h := &Inbound{}
	if err := h.ReloadUsers(option.ShadowTLSInboundOptions{}); err == nil {
		t.Fatal("value options are not what the registry produces; must be rejected")
	}
}

// v1/v2 authenticate with a single password and keep no user list, so a swap
// would be silently ineffective; and an empty list would lock everyone out.
func TestReloadUsersRejectsUnsupportedShapes(t *testing.T) {
	h := &Inbound{}
	if err := h.ReloadUsers(&option.ShadowTLSInboundOptions{Version: 2}); err == nil {
		t.Fatal("version 2 has no user list; must be refused")
	}
	if err := h.ReloadUsers(&option.ShadowTLSInboundOptions{Version: 3}); err == nil {
		t.Fatal("empty user list must be refused")
	}
}
