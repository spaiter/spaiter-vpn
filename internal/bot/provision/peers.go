package provision

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// Peer is everything a client needs to build its side of a WireGuard tunnel,
// read from the endpoint rather than assumed: the obfuscation parameters and
// the MTU have to match the server exactly or the handshake never completes.
type Peer struct {
	// PrivateKey is the client's, in standard base64.
	PrivateKey string
	// PublicKey is the client's, as registered on the endpoint.
	PublicKey string
	// Address is the client's tunnel address, without a prefix length.
	Address string
	// ServerPublicKey is derived from the endpoint's private key: the core
	// reports the private key and never the public one.
	ServerPublicKey string
	// AWG holds the AmneziaWG obfuscation parameters, passed through as the
	// core wrote them. Nil for a plain WireGuard endpoint.
	AWG json.RawMessage
	// ListenPort is the endpoint's port.
	ListenPort int
	// MTU is the endpoint's MTU, which the client must not exceed.
	MTU int
}

// endpointPeer is the part of a peer entry this package reads. The rest of the
// entry is preserved by writing back the decoded endpoint unchanged.
type endpointPeer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs AddrList `json:"allowed_ips"`
}

// EnsurePeer returns the user's peer on a WireGuard endpoint, registering one
// if the endpoint does not already have it.
//
// The stored peer file is believed only if the endpoint confirms it. A key in a
// file that the core has never heard of -- a config restored from a backup, an
// endpoint recreated -- would otherwise be handed to a client that then fails
// to handshake with no diagnostic beyond silence.
func (p *Provisioner) EnsurePeer(ctx context.Context, tag, uid string) (Peer, error) {
	// Serialized per endpoint: the read-modify-write below is the one place two
	// users can collide on an address.
	mu := p.lock(tag)
	mu.Lock()
	defer mu.Unlock()

	raw, err := p.api.Endpoint(ctx, tag)
	if err != nil {
		return Peer{}, fmt.Errorf("provision: endpoint %s: %w", tag, err)
	}
	// Decoded loosely and written back whole, so fields this package does not
	// know about -- and the installer's, and a future core's -- survive.
	var endpoint map[string]any
	if err := json.Unmarshal(raw, &endpoint); err != nil {
		return Peer{}, fmt.Errorf("provision: endpoint %s is not an object: %w", tag, err)
	}

	var typed struct {
		PrivateKey string          `json:"private_key"`
		Address    AddrList        `json:"address"`
		Peers      []endpointPeer  `json:"peers"`
		ListenPort int             `json:"listen_port"`
		MTU        int             `json:"mtu"`
		AWG        json.RawMessage `json:"awg"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return Peer{}, fmt.Errorf("provision: read endpoint %s: %w", tag, err)
	}
	if typed.PrivateKey == "" {
		return Peer{}, fmt.Errorf("provision: endpoint %s has no private key", tag)
	}
	server, err := keys.X25519FromPrivate(typed.PrivateKey)
	if err != nil {
		return Peer{}, fmt.Errorf("provision: endpoint %s private key: %w", tag, err)
	}

	peer := Peer{
		ServerPublicKey: server.PublicStd(),
		AWG:             typed.AWG,
		ListenPort:      typed.ListenPort,
		MTU:             typed.MTU,
	}

	saved, found, err := p.store.Peer(uid, tag)
	if err != nil {
		return Peer{}, err
	}
	if found && saved.Pub != "" {
		for _, existing := range typed.Peers {
			if existing.PublicKey == saved.Pub {
				peer.PrivateKey, peer.PublicKey, peer.Address = saved.Priv, saved.Pub, saved.IP
				return peer, nil
			}
		}
	}

	pair, err := keys.NewX25519()
	if err != nil {
		return Peer{}, fmt.Errorf("provision: generate a key for %s on %s: %w", uid, tag, err)
	}
	if len(typed.Address) == 0 {
		return Peer{}, fmt.Errorf("provision: endpoint %s has no address to allocate from", tag)
	}
	var used []string
	for _, existing := range typed.Peers {
		used = append(used, existing.AllowedIPs...)
	}
	address, err := NextIP(typed.Address[0], used)
	if err != nil {
		return Peer{}, err
	}

	// A stored key the endpoint has forgotten is replaced rather than added
	// beside, so a restored config does not accumulate a peer per attempt.
	rebuilt := make([]any, 0, len(typed.Peers)+1)
	raws, _ := endpoint["peers"].([]any)
	for i, existing := range typed.Peers {
		if found && existing.PublicKey == saved.Pub {
			continue
		}
		if i < len(raws) {
			rebuilt = append(rebuilt, raws[i])
		}
	}
	rebuilt = append(rebuilt, map[string]any{
		"public_key":  pair.PublicStd(),
		"allowed_ips": address + "/32",
		// name attributes the tunnel's traffic to this user the same way the
		// proxy inbounds' accounts do: it is what fills the daily stats and
		// lets the blocker ban by user rather than by address.
		"name": uid,
	})
	endpoint["peers"] = rebuilt

	if err := p.api.PutEndpoint(ctx, tag, endpoint); err != nil {
		return Peer{}, fmt.Errorf("provision: register %s on %s: %w", uid, tag, err)
	}
	// Stored only once the core has accepted it. The other order would leave a
	// key on disk that no endpoint knows, and the check above would then hand
	// it to the client as if it were live.
	if err := p.store.SetPeer(uid, tag, state.Peer{
		Priv: pair.PrivateStd(),
		Pub:  pair.PublicStd(),
		IP:   address,
	}); err != nil {
		return Peer{}, err
	}
	if err := p.rl.Request(ctx); err != nil {
		return Peer{}, fmt.Errorf("provision: apply the new peer on %s: %w", tag, err)
	}

	p.log.Info("provisioned a WireGuard peer", "uid", uid, "endpoint", tag, "address", address)
	peer.PrivateKey, peer.PublicKey, peer.Address = pair.PrivateStd(), pair.PublicStd(), address
	return peer, nil
}

// WDTT is a user's access to the WG-over-VK path: a WireGuard peer on the
// relay's endpoint plus the password the relay authenticates them by.
type WDTT struct {
	Peer     Peer
	Password string
}

// EnsureWDTT provisions the WG-over-VK path for a user.
//
// Two systems have to agree: the core holds the WireGuard peer, and the relay
// shim holds the password mapped to that peer's key and address. The relay is
// told by rewriting its password file and touching a marker, because the bot
// has no Docker socket and the relay reloads on SIGHUP rather than restarting
// -- a restart would drop every call in progress, including other users'.
func (p *Provisioner) EnsureWDTT(ctx context.Context, tag, uid, passwordsPath string) (WDTT, error) {
	peer, err := p.EnsurePeer(ctx, tag, uid)
	if err != nil {
		return WDTT{}, err
	}

	password, found, err := p.store.WDTTPassword(uid)
	if err != nil {
		return WDTT{}, err
	}
	if !found || password == "" {
		if password, err = keys.Password(12); err != nil {
			return WDTT{}, fmt.Errorf("provision: generate a relay password: %w", err)
		}
		if err := p.store.SetWDTTPassword(uid, password); err != nil {
			return WDTT{}, err
		}
	}

	// Read-modify-write: the file carries other users' passwords and fields the
	// relay owns, and replacing it wholesale would cut everyone else off.
	err = p.store.UpdateRelayPasswords(passwordsPath, func(db *state.RelayPasswords) error {
		return db.Set(password, state.RelayEntry{
			MaxDevices: 1,
			WGPriv:     peer.PrivateKey,
			WGIP:       peer.Address,
		})
	})
	if err != nil {
		return WDTT{}, err
	}
	if err := p.store.Touch(WDTTReloadMarker, state.Now()); err != nil {
		return WDTT{}, fmt.Errorf("provision: signal the relay to reload: %w", err)
	}

	return WDTT{Peer: peer, Password: password}, nil
}

// WDTTReloadMarker is the file a host-side path unit watches to send the relay
// a SIGHUP.
const WDTTReloadMarker = ".reload-wdtt"

// Registrar mints a Cloudflare account, which takes running a core that speaks
// the registration protocol.
type Registrar interface {
	Register(ctx context.Context) (json.RawMessage, error)
}

// EnsureWARP returns the user's Cloudflare account, registering one if they do
// not have it yet.
//
// Cached per user and never refreshed: registration is a network call to
// Cloudflare that takes seconds and can fail, and it sits behind a button
// someone is waiting on. An account that stops working is dealt with by
// deleting the file, which is deliberate rather than automatic -- re-registering
// on every error would hammer the API from an address that is already suspect.
func (p *Provisioner) EnsureWARP(ctx context.Context, uid string, registrar Registrar) (state.WARPAccount, error) {
	account, found, err := p.store.WARPAccount(uid)
	if err != nil {
		return nil, err
	}
	if found && len(account) > 0 {
		return account, nil
	}

	minted, err := registrar.Register(ctx)
	if err != nil {
		return nil, fmt.Errorf("provision: register a WARP account for %s: %w", uid, err)
	}
	if err := p.store.SetWARPAccount(uid, state.WARPAccount(minted)); err != nil {
		return nil, err
	}
	p.log.Info("registered a WARP account", "uid", uid)
	return state.WARPAccount(minted), nil
}
