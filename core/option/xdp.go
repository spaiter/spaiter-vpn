package option

import "github.com/sagernet/sing/common/json/badoption"

type XDPBlockerServiceOptions struct {
	Interfaces      badoption.Listable[string] `json:"interfaces"`
	BanDuration     badoption.Duration         `json:"ban_duration,omitempty"`
	CleanupInterval badoption.Duration         `json:"cleanup_interval,omitempty"`
	LogBlocked      *bool                      `json:"log_blocked,omitempty"`
}
