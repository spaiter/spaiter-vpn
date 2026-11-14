package clientcfg

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
)

// PlatformIOS is the only platform Full renders for today: a sing-box-for-apple
// client carrying the same core as the Android app.
const PlatformIOS = "ios"

// Tags the full config adds around the bundle's nodes.
const (
	fullDirectTag    = "direct"
	fullDNSRemoteTag = "dns-remote"
	fullDNSLocalTag  = "dns-local"
	fullTunTag       = "tun-in"
)

// fullTunMTU is the tunnel MTU. A mobile line behind DS-Lite carries 1280 at
// best, and MASQUE-WG and WG-over-VK already pick their inner MTUs under it.
const fullTunMTU = 1280

// fullDNSServer is the resolver reached through the tunnel: a plain address,
// so resolving it needs nothing.
const fullDNSServer = "1.1.1.1"

// Full renders a subscription bundle as a complete client config: the bundle's
// nodes with a TUN inbound, DNS and routing around them.
//
// The bundle is written for a client that builds the rest of the config
// itself, as the Android app does. A client that imports a config as it is --
// sing-box-for-apple -- needs all of it from the server instead, and must not
// need anything the stock parser lacks:
//
//   - chains are expanded the way the Android app does it (its
//     ConfigBuilder.buildBundleChain): the first leg takes the chain's tag, the
//     others become "<tag>-c<n>", detours follow;
//   - nothing relies on options the core only accepts behind an
//     ENABLE_DEPRECATED_* switch, which the Android app sets and a stock
//     client does not: DNS servers are typed, outbounds resolve through
//     route.default_domain_resolver;
//   - TUIC stays out of the url-test group on iOS, where a phone is mostly on a
//     mobile line and QUIC there does not fit the path MTU. It stays as a node
//     to pick by hand.
func Full(bundle []byte, platform string) ([]byte, error) {
	if platform != PlatformIOS {
		return nil, fmt.Errorf("clientcfg: full config: unknown platform %q", platform)
	}
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return nil, fmt.Errorf("clientcfg: full config: parse bundle: %w", err)
	}

	kinds := map[string]string{}
	var outbounds []any
	var group map[string]any
	for _, node := range parsed.Outbounds {
		tag, _ := node["tag"].(string)
		kind, _ := node["type"].(string)
		if tag == "" {
			return nil, fmt.Errorf("clientcfg: full config: a %q node has no tag", kind)
		}
		if tag == fullDirectTag {
			return nil, fmt.Errorf("clientcfg: full config: node tag %q is reserved", tag)
		}
		kinds[tag] = kind
		switch kind {
		case "urltest":
			group = node
		case "chain":
			legs, err := expandChain(node, tag)
			if err != nil {
				return nil, err
			}
			outbounds = append(outbounds, legs...)
		default:
			outbounds = append(outbounds, node)
		}
	}
	if len(outbounds) == 0 {
		return nil, fmt.Errorf("clientcfg: full config: the bundle has no nodes")
	}

	final := ""
	if group != nil {
		members, _ := group["outbounds"].([]any)
		var kept []any
		for _, member := range members {
			name, _ := member.(string)
			if kinds[name] == "tuic" {
				continue
			}
			kept = append(kept, name)
		}
		if len(kept) > 0 {
			group["outbounds"] = kept
			outbounds = append(outbounds, group)
			final, _ = group["tag"].(string)
		}
	}
	if final == "" {
		// No group to race: the first node is the default, as a client
		// without url-test would pick it.
		final, _ = outbounds[0].(map[string]any)["tag"].(string)
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": fullDirectTag})

	config := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{
					"type": "https", "tag": fullDNSRemoteTag,
					"server": fullDNSServer, "detour": final,
				},
				map[string]any{"type": "local", "tag": fullDNSLocalTag},
			},
			"final": fullDNSRemoteTag,
		},
		"inbounds": []any{
			map[string]any{
				"type": "tun", "tag": fullTunTag,
				"address":    []any{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"mtu":        fullTunMTU,
				"auto_route": true, "strict_route": true,
				"stack": "system",
			},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": fullDirectTag},
			},
			"final":                   final,
			"auto_detect_interface":   true,
			"default_domain_resolver": fullDNSLocalTag,
		},
		"experimental": map[string]any{
			// Remembers the node picked in the group across restarts of
			// the tunnel.
			"cache_file": map[string]any{"enabled": true},
		},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("clientcfg: full config: render: %w", err)
	}
	return data, nil
}

// expandChain turns a chain node into one outbound per leg.
func expandChain(node map[string]any, tag string) ([]any, error) {
	raw, _ := node["_chain"].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("clientcfg: full config: chain %q has no legs", tag)
	}
	legs := make([]map[string]any, len(raw))
	remap := map[string]string{}
	for i, item := range raw {
		leg, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("clientcfg: full config: chain %q leg %d is not an object", tag, i)
		}
		legs[i] = leg
		own, _ := leg["tag"].(string)
		if own == "" {
			continue
		}
		if i == 0 {
			remap[own] = tag
		} else {
			remap[own] = tag + "-c" + strconv.Itoa(i-1)
		}
	}
	out := make([]any, 0, len(legs))
	for i, leg := range legs {
		if detour, _ := leg["detour"].(string); detour != "" {
			if mapped, ok := remap[detour]; ok {
				leg["detour"] = mapped
			}
		}
		if i == 0 {
			leg["tag"] = tag
		} else {
			leg["tag"] = tag + "-c" + strconv.Itoa(i-1)
		}
		out = append(out, leg)
	}
	return out, nil
}

// fullPlatforms lists what Full accepts, for a caller deciding whether to ask.
var fullPlatforms = []string{PlatformIOS}

// FullPlatformKnown reports whether Full renders for platform.
func FullPlatformKnown(platform string) bool {
	return slices.Contains(fullPlatforms, platform)
}
