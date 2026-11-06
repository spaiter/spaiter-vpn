package bot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultsMatchThePythonBot is the one that matters during the port: if a
// default drifts, the host it was written for changes behaviour the moment the
// Go bot takes over, and nothing else would say so.
//
// "The Python bot" means the one that is running, not the source file. That
// distinction cost four wrong defaults, found only by rebuilding all six live
// subscriptions and diffing them: bot.py reads thirty environment variables,
// its compose file supplies some of them, and the environment of the running
// container overrides those again. The MASQUE port was a source constant I had
// guessed at; the VK port and obfuscation profile came from the container's
// environment and did not match the compose default either -- the port moved
// and the default was never corrected.
//
// So the authority for anything configurable is `docker exec vpn-bot env`, and
// for anything hard-coded it is bot.py. Each value below says which.
func TestDefaultsMatchThePythonBot(t *testing.T) {
	c := Defaults()

	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"core.config_path", c.Core.ConfigPath, "/sing-box/config.json"},
		{"core.container", c.Core.Container, "sing-box"},
		{"paths.data_dir", c.Paths.DataDir, "/data"},
		{"paths.wdtt_config_dir", c.Paths.WDTTConfigDir, "/wdtt-cfg"},
		{"paths.apk", c.Paths.APK, "/apk/latest.apk"},
		{"paths.warp_binary", c.Paths.WARPBinary, "/app/singbox-fork"},
		{"paths.checkhash_binary", c.Paths.CheckHashBinary, "/app/wdtt-checkhash"},
		{"public.host", c.Public.Host, ""},
		// The resolver bot.py wrote into every WireGuard profile. An empty one
		// leaves a tunnel that connects and resolves nothing.
		{"public.dns", c.Public.DNS, "1.1.1.1"},
		// WDTT_SERVER_HOST in the environment. An A-only name, because both
		// the VK relay and the WireGuard endpoints are IPv4-only and a
		// dual-stack name resolves to AAAA first.
		{"public.ipv4_host", c.Public.IPv4Host, ""},
		// Node tags, not captions: a client keys its saved selection by these,
		// so a rename is a new node appearing and the old one vanishing.
		{"node_tags.shadowtls", c.NodeTags.ShadowTLS, "ShadowTLS"},
		{"node_tags.warp", c.NodeTags.WARP, "WARP → сервер"},
		{"node_tags.masque_wg", c.NodeTags.MASQUEWG, "MASQUE-WG"},
		{"node_tags.wdtt", c.NodeTags.WDTT, "WG-over-VK"},
		{"node_tags.awg", c.NodeTags.AWG, "AmneziaWG"},
		{"node_tags.awg3", c.NodeTags.AWG3, "AmneziaWG 3.1"},
		// The tags bot.py held as source constants, which is why it only ever
		// ran against this one deployment.
		{"tags.awg", c.Tags.AWG, "awg-in"},
		{"tags.awg3", c.Tags.AWG3, "awg3-in"},
		{"tags.masque_wg", c.Tags.MASQUEWG, "wg-masque-in"},
		{"tags.shadowtls", c.Tags.ShadowTLS, "shadowtls-in"},
		{"masque_wg.path", c.MASQUEWG.Path, "/m"},
		{"subscription.port", c.Subscription.Port, uint16(10873)},
		{"subscription.host_cf", c.Subscription.HostCF, ""},
		{"subscription.host_direct", c.Subscription.HostDirect, ""},
		{"warp.sni", c.WARP.SNI, "mail.ru"},
		// Source constant: MASQUEWG_PORT. A high port because a DS-Lite line
		// has no inbound :443.
		{"masque_wg.port_is_not_443", c.MASQUEWG.Port, uint16(10876)},
		{"warp.port", c.WARP.Port, uint16(443)},
		{"warp.inner_tag", c.WARP.InnerTag, "vless-reality-in"},
		// Both from the running container's environment, which overrides the
		// compose defaults of 10865 and rtpopus3 respectively.
		{"wdtt.dtls_port", c.WDTT.DTLSPort, uint16(10867)},
		{"wdtt.obfs", c.WDTT.Obfs, "rtpopus3"},
		{"wdtt.mtu", c.WDTT.MTU, uint32(1000)},
		{"wdtt.workers_per_hash", c.WDTT.WorkersPerHash, 9},
		{"wdtt.max_workers", c.WDTT.MaxWorkers, 108},
		{"wdtt.workers", c.WDTT.Workers, 0},
		{"wdtt.container", c.WDTT.Container, "wdtt-relay"},
		{"wdtt.tag", c.WDTT.Tag, "wg-wdtt-in"},
		{"intervals.sub_refresh", c.Intervals.SubRefresh.Build(), 60 * time.Second},
		{"intervals.hash_check", c.Intervals.HashCheck.Build(), time.Hour},
		{"intervals.notify_poll", c.Intervals.NotifyPoll.Build(), 15 * time.Second},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}

	// Hosts name a deployment, so the defaults carry none: not the CDN
	// front either, which is a map because only some inbounds have one.
	if len(c.Public.CDN) != 0 {
		t.Errorf("public.cdn = %v, want none by default", c.Public.CDN)
	}

	// Chains and AWG3 are off by default here even though the live compose
	// turns both on: a fresh deployment has clients of unknown vintage, and
	// both nodes need a recent core.
	if c.Bundle.EnableChains || c.Bundle.EnableAWG3 {
		t.Error("bundle chains/awg3 default to on; they require a recent client core")
	}

	if got := c.Paths.ReloadMarker(); got != "/data/.reload-singbox" {
		t.Errorf("reload marker = %q", got)
	}
	if got := c.Paths.WDTTReloadMarker(); got != "/data/.reload-wdtt" {
		t.Errorf("wdtt reload marker = %q", got)
	}
	if got := c.Paths.NotifyMarker(); got != "/data/.notify-subs" {
		t.Errorf("notify marker = %q", got)
	}
}

// TestDefaultUICoversEveryOfferedInbound guards the failure mode where a
// protocol exists, is handed out, and shows up in the picker as a bare tag.
func TestDefaultUICoversEveryOfferedInbound(t *testing.T) {
	ui := Defaults().UI
	for tag := range JSONTags() {
		// vless-xhttp-obfs-in intentionally has no label: it is delivered as a
		// file and labelled by the inbound it shadows.
		if tag == "vless-xhttp-obfs-in" {
			continue
		}
		if ui.TagLabel[tag] == "" {
			t.Errorf("no ui.tag_label for %s", tag)
		}
	}
	for kind := range UserTypes() {
		if ui.ProtoLabel[kind] == "" {
			t.Errorf("no ui.proto_label for inbound type %s", kind)
		}
	}
	for _, key := range []string{"getcfg", "allsub", "mystats", "apk", "menu"} {
		if ui.Buttons[key] == "" {
			t.Errorf("no ui.buttons[%s]", key)
		}
	}
}

func TestLoadMissingFileKeepsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing config is not an error: %v", err)
	}
	if cfg.Public.Host != Defaults().Public.Host {
		t.Error("defaults were not kept")
	}
}

// TestLoadMergesUIOverDefaults is the property that keeps a third-party config
// file from going stale: overriding one label must not erase the others.
func TestLoadMergesUIOverDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.json")
	write(t, path, `{
	  "public": {"host": "vpn.example.org"},
	  "ui": {"tag_label": {"awg-in": "My WireGuard"}}
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Public.Host != "vpn.example.org" {
		t.Errorf("host = %q, want the override", cfg.Public.Host)
	}
	if got := cfg.UI.TagLabel["awg-in"]; got != "My WireGuard" {
		t.Errorf("awg-in label = %q, want the override", got)
	}
	if got := cfg.UI.TagLabel["vless-reality-in"]; got != "VLESS Reality" {
		t.Errorf("vless-reality-in label = %q, want the default to survive", got)
	}
	// An untouched section keeps its defaults too.
	if cfg.Subscription.Port != 10873 {
		t.Errorf("subscription port = %d, want the default", cfg.Subscription.Port)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.json")
	write(t, path, `{"public": {"hostname": "typo.example.org"}}`)

	if _, err := Load(path); err == nil {
		t.Fatal("a misspelled key was accepted; the default would silently stand")
	} else if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestDurationRoundTripsAsText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.json")
	write(t, path, `{"public": {"host": "vpn.example.com"}, "intervals": {"sub_refresh": "90s"}}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Intervals.SubRefresh.Build(); got != 90*time.Second {
		t.Errorf("sub_refresh = %v, want 90s", got)
	}

	data, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"sub_refresh": "1m30s"`) {
		t.Error("durations should marshal as text, not nanoseconds")
	}

	// And what we write, we can read.
	round := filepath.Join(t.TempDir(), "round.json")
	write(t, round, string(data))
	again, err := Load(round)
	if err != nil {
		t.Fatalf("reload what Marshal produced: %v", err)
	}
	if again.Intervals.SubRefresh != cfg.Intervals.SubRefresh {
		t.Error("round trip changed the interval")
	}
}

func TestValidateRejectsTheConfigsThatWouldFailLater(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no public host", func(c *Config) { c.Public.Host = "" }, "public.host"},
		{"no data dir", func(c *Config) { c.Paths.DataDir = "" }, "data_dir"},
		{"no core config", func(c *Config) { c.Core.ConfigPath = "" }, "config_path"},
		{"no sub port", func(c *Config) { c.Subscription.Port = 0 }, "subscription.port"},
		{"zero interval", func(c *Config) { c.Intervals.SubRefresh = 0 }, "sub_refresh"},
		{"workers over cap", func(c *Config) {
			c.WDTT.WorkersPerHash, c.WDTT.MaxWorkers = 200, 108
		}, "exceeds max_workers"},
		{"cdn front without port", func(c *Config) {
			c.Public.CDN["vless-ws-cdn-in"] = CDNFront{Host: "x"}
		}, "needs a host and a port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ExampleConfig()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
		})
	}

	if err := ExampleConfig().Validate(); err != nil {
		t.Errorf("the defaults with hosts must validate: %v", err)
	}
	if err := Defaults().Validate(); err == nil || !strings.Contains(err.Error(), "public.host") {
		t.Errorf("the defaults name no host, so they must not validate: %v", err)
	}
}

// TestMarshalIsValidJSON keeps `init` from writing a file the bot cannot read.
func TestMarshalIsValidJSON(t *testing.T) {
	data, err := Defaults().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var any map[string]json.RawMessage
	if err := json.Unmarshal(data, &any); err != nil {
		t.Fatalf("Marshal produced invalid JSON: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Error("the rendered config should end with a newline")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
