package clientcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/spaiter/spaiter-vpn/internal/bot"
)

// Bundle is the all-methods subscription: one node per method, plus a
// url-test group over the ones worth racing.
type Bundle struct {
	Outbounds []any `json:"outbounds"`
}

// AutoTag is the url-test group's name, which is what the user taps.
const AutoTag = "🚀 Авто (лучший)"

// AutoURL is probed to decide which node is fastest.
const AutoURL = "https://www.gstatic.com/generate_204"

// AutoInterval is how often the client re-races the group.
const AutoInterval = "3m0s"

// Assemble puts the url-test group on top of the nodes it is given.
//
// The group is added only when there is something to race, and the
// censorship-bypass methods are left out of it. They take far longer to
// establish than the probe allows -- VK relays about a minute, MASQUE a QUIC
// handshake, WARP whatever Cloudflare costs where it is reachable at all -- so
// they can never win the race and instead hang it, leaving the group spinning
// instead of settling on a method that works. They stay as standalone nodes,
// which is how someone reaches for them when the fast ones are blocked.
//
// A core that does not know urltest ignores the extra outbound, so this
// degrades to a plain node list rather than failing.
func Assemble(cfg bot.Config, nodes []any) Bundle {
	if len(nodes) == 0 {
		return Bundle{Outbounds: []any{}}
	}

	var raced []string
	for _, node := range nodes {
		tag := nodeTag(node)
		if tag == "" || slices.Contains(cfg.Bundle.AutoExcludeTags, tag) {
			continue
		}
		raced = append(raced, tag)
	}

	out := append([]any{}, nodes...)
	if len(raced) > 0 {
		out = append(out, map[string]any{
			"type": "urltest", "tag": AutoTag,
			"outbounds": raced,
			"url":       AutoURL, "interval": AutoInterval,
		})
	}
	return Bundle{Outbounds: out}
}

// Marshal renders the bundle as it is served.
func (b Bundle) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("clientcfg: render bundle: %w", err)
	}
	return data, nil
}

// StructuralHash identifies a bundle by what a user would have to act on.
//
// The VK hash pool rotates hourly and the worker count moves with its size.
// Both are refreshed in the served config regardless -- clients pick them up
// on their own timer -- so including them would mean telling every subscriber
// their configuration changed several times a day when nothing they can act on
// did. Those two fields are therefore blanked before hashing.
//
// This is not the Python's hash and does not try to be: that one is a sha256
// over Python's own JSON rendering, and matching its spacing byte for byte
// would be a lasting cost for one day's convenience. The first run adopts the
// current state instead, recording hashes without notifying anyone.
func StructuralHash(bundle []byte) (string, error) {
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return "", fmt.Errorf("clientcfg: hash bundle: %w", err)
	}
	for _, node := range parsed.Outbounds {
		if node["type"] != "wdtt" {
			continue
		}
		node["vk_hashes"] = []any{}
		delete(node, "workers")
	}
	// Marshal sorts object keys, so the digest does not depend on the order
	// the nodes were built in.
	canonical, err := json.Marshal(parsed)
	if err != nil {
		return "", fmt.Errorf("clientcfg: canonicalise bundle: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// NodeLabel is what a node is called in the user's client: the configured
// label for the tag, else the protocol's name, else the inbound type.
func NodeLabel(cfg bot.Config, in Inbound) string {
	if label := cfg.UI.TagLabel[in.Tag]; label != "" {
		return label
	}
	if label := cfg.UI.ProtoLabel[in.Type]; label != "" {
		return label
	}
	return in.Type
}

// nodeTag reads the tag of a node or a chain, whichever it was given.
func nodeTag(node any) string {
	switch val := node.(type) {
	case Node:
		tag, _ := val["tag"].(string)
		return tag
	case Chain:
		return val.Tag
	case map[string]any:
		tag, _ := val["tag"].(string)
		return tag
	default:
		return ""
	}
}
