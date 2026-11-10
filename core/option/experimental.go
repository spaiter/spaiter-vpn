package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type ExperimentalOptions struct {
	CacheFile *CacheFileOptions `json:"cache_file,omitempty"`
	ClashAPI  *ClashAPIOptions  `json:"clash_api,omitempty"`
	V2RayAPI  *V2RayAPIOptions  `json:"v2ray_api,omitempty"`
	Debug     *DebugOptions     `json:"debug,omitempty"`

	Monitoring   *MonitoringOptions   `json:"monitoring,omitempty"`    //H
	UnifiedDelay *UnifiedDelayOptions `json:"unified_delay,omitempty"` //H
}

type UnifiedDelayOptions struct { //H
	Enabled bool `json:"enabled,omitempty"`
}

type CacheFileOptions struct {
	Enabled           bool                     `json:"enabled,omitempty"`
	Path              string                   `json:"path,omitempty"`
	CacheID           string                   `json:"cache_id,omitempty"`
	StoreFakeIP       bool                     `json:"store_fakeip,omitempty"`
	StoreDNS          bool                     `json:"store_dns,omitempty"`
	StoreWARPConfig   *bool                    `json:"store_warp_config,omitempty"`   //H: on unless false
	StoreMASQUEConfig *bool                    `json:"store_masque_config,omitempty"` //H: on unless false
	BufferSize        *byteformats.MemoryBytes `json:"buffer_size,omitempty"`
	FlushInterval     badoption.Duration       `json:"flush_interval,omitempty"`

	// Deprecated: replaced by store_dns
	StoreRDRC bool `json:"store_rdrc,omitempty" schema:"omit"`
	// Deprecated: replaced by store_dns
	RDRCTimeout badoption.Duration `json:"rdrc_timeout,omitempty" schema:"omit"`
}

type ClashAPIOptions struct {
	ExternalController               string                     `json:"external_controller,omitempty"`
	ExternalUI                       string                     `json:"external_ui,omitempty"`
	ExternalUIDownloadURL            string                     `json:"external_ui_download_url,omitempty"`
	ExternalUIDownloadDetour         string                     `json:"external_ui_download_detour,omitempty" reference:"outbound"`
	Secret                           string                     `json:"secret,omitempty"`
	DefaultMode                      string                     `json:"default_mode,omitempty"`
	AccessControlAllowOrigin         badoption.Listable[string] `json:"access_control_allow_origin,omitempty"`
	AccessControlAllowPrivateNetwork bool                       `json:"access_control_allow_private_network,omitempty"`
	ConfigOutputPath                 string                     `json:"config_output_path,omitempty"`

	// UserLimits caps bandwidth per user, keyed by the same user name the
	// per-user stats are keyed by. It lives here, next to those stats, rather
	// than on each inbound's user entry: every protocol carries its own user
	// type, so a per-user field would have to be added to a dozen option
	// structs and read back out of every one of them, while the limiter only
	// ever needs the name that InboundContext.User already carries. //H
	UserLimits map[string]UserLimitOptions `json:"user_limits,omitempty"` //H

	// Deprecated: migrated to global cache file
	CacheFile string `json:"cache_file,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	CacheID string `json:"cache_id,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	StoreMode bool `json:"store_mode,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	StoreSelected bool `json:"store_selected,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	StoreFakeIP bool `json:"store_fakeip,omitempty" schema:"omit"`
}

// UserLimitOptions is one user's bandwidth cap, in megabits per second as the
// user-facing unit. Zero means unlimited in that direction, so a user with
// only DownloadMbps set is throttled on the way down and untouched on the way
// up. Directions are named from the client's point of view: download is what
// the server writes to the client. //H
type UserLimitOptions struct { //H
	DownloadMbps float64 `json:"download_mbps,omitempty"`
	UploadMbps   float64 `json:"upload_mbps,omitempty"`
}

type V2RayAPIOptions struct {
	Listen string                    `json:"listen,omitempty"`
	Stats  *V2RayStatsServiceOptions `json:"stats,omitempty"`
}

type V2RayStatsServiceOptions struct {
	Enabled   bool     `json:"enabled,omitempty"`
	Inbounds  []string `json:"inbounds,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
	Users     []string `json:"users,omitempty"`
}
