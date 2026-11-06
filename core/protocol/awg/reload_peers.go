package awg

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// peerState is the peer list currently programmed into the device, keyed by
// public key, so ReloadPeers can work out a delta instead of reprogramming
// everything. //H
type peerState struct {
	mu    sync.Mutex
	peers map[string]option.AwgPeerOptions
}

func newPeerState(peers []option.AwgPeerOptions) *peerState {
	state := &peerState{peers: make(map[string]option.AwgPeerOptions, len(peers))}
	for _, peer := range peers {
		state.peers[peer.PublicKey] = peer
	}
	return state
}

// ReloadPeers implements adapter.PeerReloader. It programs only the peers that
// were added, changed or removed: peers left alone keep their session keys and
// their handshake, so established tunnels survive the change. Replacing the
// whole peer set (UAPI `replace_peers=true`) would instead drop and recreate
// every peer, forcing all of them to re-handshake. //H
func (e *Endpoint) ReloadPeers(options any) error {
	// The endpoint registry stores options as a pointer (see
	// adapter/endpoint.Register), so that is what apply hands over.
	optsPtr, ok := options.(*option.AwgEndpointOptions)
	if !ok {
		return E.New("awg: unexpected options type for peer reload")
	}
	opts := *optsPtr
	if e.Device == nil {
		return E.New("awg: endpoint not started")
	}

	e.peerState.mu.Lock()
	defer e.peerState.mu.Unlock()

	desired := make(map[string]option.AwgPeerOptions, len(opts.Peers))
	for _, peer := range opts.Peers {
		if peer.PublicKey == "" {
			return E.New("awg: peer without public_key")
		}
		if _, duplicate := desired[peer.PublicKey]; duplicate {
			return E.New("awg: duplicate peer public_key")
		}
		desired[peer.PublicKey] = peer
	}

	// A domain-addressed peer needs a resolver, which only the constructor
	// sets up; refuse rather than silently dropping the endpoint address.
	for key, peer := range desired {
		if peer.Address != "" && !M.ParseAddr(peer.Address).IsValid() {
			return E.New("awg: peer ", key, " has a domain address, cannot reload")
		}
	}

	var ipc strings.Builder
	var added, changed, removed int
	for key, peer := range desired {
		if existing, exists := e.peerState.peers[key]; exists {
			if peersEqual(existing, peer) {
				continue
			}
			section, err := genIpcPeer(peer, nil)
			if err != nil {
				return err
			}
			// allowed_ips are additive in the UAPI, so an edit has to clear the
			// old set or a removed range would linger and keep routing. The
			// flag has to sit between this peer's public_key and its allowed_ip
			// lines — emitted before the key it would apply to the previous
			// peer, after the ranges it would wipe the ones just set.
			hexKey, err := publicKeyHex(peer.PublicKey)
			if err != nil {
				return err
			}
			keyLine := "\npublic_key=" + hexKey
			ipc.WriteString(keyLine + "\nreplace_allowed_ips=true" + strings.TrimPrefix(section, keyLine))
			changed++
			continue
		}
		section, err := genIpcPeer(peer, nil)
		if err != nil {
			return err
		}
		ipc.WriteString(section)
		added++
	}
	for key := range e.peerState.peers {
		if _, keep := desired[key]; keep {
			continue
		}
		hexKey, err := publicKeyHex(key)
		if err != nil {
			return err
		}
		ipc.WriteString("\npublic_key=" + hexKey + "\nremove=true")
		removed++
	}

	if added == 0 && changed == 0 && removed == 0 {
		return nil
	}
	// IpcSet wants the config without the leading newline genIpcPeer emits.
	if err := e.Device.IpcSetDelta(strings.TrimPrefix(ipc.String(), "\n")); err != nil {
		return E.Cause(err, "awg: program peer delta")
	}

	e.peerState.peers = desired
	e.peerNames.Store(newPeerNameTable(opts.Peers))
	e.logger.Info("peers reloaded: ", added, " added, ", changed, " changed, ", removed, " removed")
	return nil
}

func publicKeyHex(base64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", E.Cause(err, "decode peer public_key")
	}
	return hex.EncodeToString(raw), nil
}

// peersEqual compares everything the device is programmed with. `name` is
// deliberately excluded: it only feeds attribution, never the device, so a
// rename must not trigger a UAPI write. //H
func peersEqual(a, b option.AwgPeerOptions) bool {
	if a.PublicKey != b.PublicKey || a.PresharedKey != b.PresharedKey ||
		a.Address != b.Address || a.Port != b.Port ||
		a.PersistentKeepaliveInterval != b.PersistentKeepaliveInterval ||
		len(a.AllowedIPs) != len(b.AllowedIPs) {
		return false
	}
	for i := range a.AllowedIPs {
		if a.AllowedIPs[i] != b.AllowedIPs[i] {
			return false
		}
	}
	return true
}
