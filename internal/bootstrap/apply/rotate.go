package apply

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	botstate "github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/keys"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// pendingRotation is what a credential rotation has to remember between
// clearing the rotated slots and seeing what the generator minted for them.
type pendingRotation struct {
	users map[string]bool
	// before is the live credential set as it was read, so the minted one can
	// be proven different for rotated users and identical for everybody else.
	before   profile.Secrets
	botPeers []botPeerFile
}

// prepareCredentialRotation empties every per-user slot of the rotated users
// so the generator mints fresh values for them, while keeping each WireGuard
// peer's address: a rotated client gets new keys, not a new place on the
// network, and nobody else's address can shift.
//
// It refuses before anything is written when a rotated user's private peer
// key has no copy bootstrap can update. The live config holds only the public
// half, so rotating such a peer would hand the server a key no client has.
func (o Options) prepareCredentialRotation(runtime *runtimeState, rotation state.CredentialRotation) (*pendingRotation, error) {
	pending := &pendingRotation{users: make(map[string]bool, len(rotation.Users)), before: cloneSecrets(runtime.credentials)}
	live := make(map[string]profile.UserSecrets, len(runtime.credentials.Users))
	for _, user := range runtime.credentials.Users {
		live[user.Name] = user
	}
	for _, name := range rotation.Users {
		if _, ok := live[name]; !ok {
			return nil, fmt.Errorf("credential rotation is blocked: %q is not a user of the live configuration", name)
		}
		pending.users[name] = true
	}

	botPeers, err := o.readBotPeers()
	if err != nil {
		return nil, err
	}
	pending.botPeers = botPeers
	handover := make(map[string]profile.UserSecrets, len(runtime.handover.Users))
	for _, user := range runtime.handover.Users {
		handover[user.Name] = user
	}
	for _, name := range rotation.Users {
		user := live[name]
		for protocol, peer := range user.Peers {
			copies := 0
			if client, ok := handover[name].Peers[protocol]; ok {
				if client.PublicKey != peer.PublicKey || client.Address != peer.Address || client.PrivateKey == "" {
					return nil, fmt.Errorf("credential rotation is blocked: %q peer %q in secrets.json does not match config.json", name, protocol)
				}
				copies++
			}
			for _, bot := range botPeers {
				if bot.uid != name || bot.protocol != protocol {
					continue
				}
				if bot.value.Pub != peer.PublicKey || bot.addr != peer.Address.Addr() {
					return nil, fmt.Errorf("credential rotation is blocked: bot peer %s does not match config.json", bot.path)
				}
				copies++
			}
			if copies == 0 {
				return nil, fmt.Errorf("credential rotation is blocked: %q peer %q has no private-key copy in secrets.json or the bot's peer store", name, protocol)
			}
		}
	}
	for _, bot := range botPeers {
		if !pending.users[bot.uid] {
			continue
		}
		if _, ok := live[bot.uid].Peers[bot.protocol]; !ok {
			return nil, fmt.Errorf("credential rotation is blocked: bot peer %s has no live peer in config.json", bot.path)
		}
	}

	for i := range runtime.credentials.Users {
		user := &runtime.credentials.Users[i]
		if !pending.users[user.Name] {
			continue
		}
		peers := make(map[profile.Protocol]profile.PeerSecrets, len(user.Peers))
		for protocol, peer := range user.Peers {
			peers[protocol] = profile.PeerSecrets{Address: peer.Address}
		}
		*user = profile.UserSecrets{Name: user.Name, Peers: peers}
	}
	return pending, nil
}

// finishCredentialRotation proves the regenerated credential set is the
// rotation that was asked for and nothing more, then writes the new values to
// every client-side copy: the seed handover, the bot's peer store, the
// WG-over-VK relay and the subscription registry.
func (o Options) finishCredentialRotation(runtime *runtimeState, pending *pendingRotation, regenerated profile.Secrets, manager *transaction.Manager) ([]byte, []transaction.Change, error) {
	if err := verifyRotation(pending, regenerated); err != nil {
		return nil, nil, fmt.Errorf("the regenerated credentials are not the requested rotation: %w", err)
	}
	minted := make(map[string]profile.UserSecrets, len(regenerated.Users))
	for _, user := range regenerated.Users {
		minted[user.Name] = user
	}

	var secretsJSON []byte
	handover := runtime.handover
	handover.Users = append([]profile.UserSecrets(nil), runtime.handover.Users...)
	rotatedSeed := false
	for i, user := range handover.Users {
		if pending.users[user.Name] {
			handover.Users[i] = minted[user.Name]
			rotatedSeed = true
		}
	}
	if rotatedSeed {
		data, err := json.MarshalIndent(handover, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("marshal rotated client credentials: %w", err)
		}
		secretsJSON = append(data, '\n')
		runtime.handover = handover
		runtime.expectedSecretsDigest = digestOf(secretsJSON)
	}

	receipt, _, err := manager.Current()
	if err != nil {
		return nil, nil, fmt.Errorf("read bot-state ownership: %w", err)
	}
	var changes []transaction.Change
	var wdtt []rotatedRelayPeer
	for _, bot := range pending.botPeers {
		if !pending.users[bot.uid] {
			continue
		}
		peer := minted[bot.uid].Peers[bot.protocol]
		// Bare IPv4 address, unchanged: the bot's renderers append "/32".
		value := botstate.Peer{Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: bot.value.IP}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, nil, err
		}
		changes = append(changes, runtimeMutableChange(bot.path, encoded, 0o600, manager, receipt))
		if bot.protocol == profile.WGWDTT {
			wdtt = append(wdtt, rotatedRelayPeer{old: bot, newPriv: peer.PrivateKey})
		}
	}
	relayChanges, err := o.rotateRelayPasswords(manager, receipt, wdtt)
	if err != nil {
		return nil, nil, err
	}
	changes = append(changes, relayChanges...)
	subsChanges, err := o.rotateSubscriptionTokens(manager, receipt, pending.users)
	if err != nil {
		return nil, nil, err
	}
	changes = append(changes, subsChanges...)
	cacheChanges, err := o.subscriptionCacheChanges(manager, receipt)
	if err != nil {
		return nil, nil, err
	}
	changes = append(changes, cacheChanges...)
	return secretsJSON, changes, nil
}

// verifyRotation is the rotation's own proof, run on the rendered bundle
// before anything is written: rotated users hold a fresh value in exactly the
// slots they held before and keep every peer address, while every other user
// and every deployment-wide secret is unchanged.
func verifyRotation(pending *pendingRotation, regenerated profile.Secrets) error {
	if len(regenerated.Users) != len(pending.before.Users) {
		return fmt.Errorf("user count changed from %d to %d", len(pending.before.Users), len(regenerated.Users))
	}
	for i, before := range pending.before.Users {
		after := regenerated.Users[i]
		if after.Name != before.Name {
			return fmt.Errorf("user %d changed from %q to %q", i, before.Name, after.Name)
		}
		if len(after.Peers) != len(before.Peers) {
			return fmt.Errorf("user %q peer set changed", before.Name)
		}
		if !pending.users[before.Name] {
			if !reflect.DeepEqual(before.CredentialSlots(), after.CredentialSlots()) {
				return fmt.Errorf("user %q was not selected but its credentials changed", before.Name)
			}
			for protocol, peer := range before.Peers {
				got := after.Peers[protocol]
				if got.PublicKey != peer.PublicKey || got.Address != peer.Address {
					return fmt.Errorf("user %q was not selected but its %s peer changed", before.Name, protocol)
				}
			}
			continue
		}
		oldSlots, newSlots := before.CredentialSlots(), after.CredentialSlots()
		for slot, old := range oldSlots {
			minted := newSlots[slot]
			if (old == "") != (minted == "") {
				return fmt.Errorf("user %q %s slot appeared or disappeared", before.Name, slot)
			}
			if old != "" && old == minted {
				return fmt.Errorf("user %q %s was not reissued", before.Name, slot)
			}
		}
		for protocol, peer := range before.Peers {
			got, ok := after.Peers[protocol]
			if !ok || got.Address != peer.Address {
				return fmt.Errorf("user %q %s peer address changed", before.Name, protocol)
			}
			if got.PublicKey == "" || got.PrivateKey == "" || got.PublicKey == peer.PublicKey {
				return fmt.Errorf("user %q %s peer keypair was not reissued", before.Name, protocol)
			}
		}
	}
	if !reflect.DeepEqual(sharedSecrets(pending.before), sharedSecrets(regenerated)) {
		return fmt.Errorf("deployment-wide secrets changed; a per-user rotation must not touch them")
	}
	return nil
}

// sharedSecrets is the deployment-wide key material: what every client shares
// and a per-user rotation must therefore leave alone. Facts such as ports are
// left out because they are not secrets and are not what this proves.
func sharedSecrets(s profile.Secrets) map[string]any {
	endpoints := map[profile.Protocol][3]string{}
	for protocol, endpoint := range s.Endpoints {
		endpoints[protocol] = [3]string{endpoint.PrivateKey, endpoint.PublicKey, endpoint.Address.String()}
	}
	return map[string]any{
		"clash":       s.ClashAPISecret,
		"reality":     s.Reality,
		"shadowsocks": s.Shadowsocks.Password,
		"snell":       s.Snell.PSK,
		"mtproto":     s.MTProto.Secret,
		"hysteria2":   s.TierB.Hysteria2ObfsPassword,
		"xhttp":       s.TierB.XHTTPReality,
		"endpoints":   endpoints,
	}
}

type rotatedRelayPeer struct {
	old     botPeerFile
	newPriv string
}

// rotateRelayPasswords reissues the WG-over-VK relay password of each rotated
// user. The old entry goes away together with the devices bound to it, exactly
// as the relay's own delete does: a device that was bound with a leaked
// password must not stay connected. The new entry keeps the operator-facing
// policy and counters and starts with no bound device.
func (o Options) rotateRelayPasswords(manager *transaction.Manager, receipt transaction.Receipt, peers []rotatedRelayPeer) ([]transaction.Change, error) {
	if len(peers) == 0 {
		return nil, nil
	}
	configDir := o.Desired.Bot.WDTTConfigDirectory
	if configDir == "" {
		return nil, fmt.Errorf("credential rotation for %s is blocked: bot.wdttConfigDirectory does not name the external relay config directory", profile.WGWDTT)
	}
	path := filepath.Join(configDir, "passwords.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read WG-over-VK relay passwords %s: %w", path, err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse WG-over-VK relay passwords %s: %w", path, err)
	}
	var entries map[string]map[string]json.RawMessage
	if raw, ok := root["passwords"]; !ok || json.Unmarshal(raw, &entries) != nil || entries == nil {
		return nil, fmt.Errorf("parse WG-over-VK relay passwords %s: passwords must be an object", path)
	}
	devices := map[string]json.RawMessage{}
	if raw, ok := root["devices"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &devices); err != nil {
			return nil, fmt.Errorf("parse WG-over-VK relay passwords %s: devices must be an object", path)
		}
	}

	var changes []transaction.Change
	for _, peer := range peers {
		passwordPath := filepath.Join(o.Layout.BotDataDir(), "wdtt", peer.old.uid+".json")
		passwordData, err := os.ReadFile(passwordPath)
		if err != nil {
			return nil, fmt.Errorf("read WG-over-VK password copy for peer %s: %w", peer.old.path, err)
		}
		var saved botstate.WDTTPassword
		if json.Unmarshal(passwordData, &saved) != nil || saved.Password == "" {
			return nil, fmt.Errorf("invalid WG-over-VK password copy %s", passwordPath)
		}
		entry, ok := entries[saved.Password]
		if !ok {
			return nil, fmt.Errorf("bot peer %s has no matching relay passwords.json entry", peer.old.path)
		}
		wgPriv, _, err := relayString(entry, "wg_priv")
		if err != nil {
			return nil, fmt.Errorf("WG-over-VK relay entry: %w", err)
		}
		wgIP, _, err := relayString(entry, "wg_ip")
		if err != nil {
			return nil, fmt.Errorf("WG-over-VK relay entry: %w", err)
		}
		if wgPriv != peer.old.value.Priv || wgIP != peer.old.value.IP {
			return nil, fmt.Errorf("WG-over-VK relay entry does not match bot peer %s", peer.old.path)
		}

		for _, id := range boundDevices(entry) {
			delete(devices, id)
		}
		password, err := keys.Password(12)
		if err != nil {
			return nil, fmt.Errorf("generate a relay password: %w", err)
		}
		if _, taken := entries[password]; taken {
			return nil, fmt.Errorf("generated relay password collides with an existing entry")
		}
		delete(entries, saved.Password)
		delete(entry, "device_id")
		delete(entry, "device_ids")
		encodedPriv, err := json.Marshal(peer.newPriv)
		if err != nil {
			return nil, err
		}
		entry["wg_priv"] = encodedPriv
		entries[password] = entry

		encodedPassword, err := json.Marshal(botstate.WDTTPassword{Password: password})
		if err != nil {
			return nil, err
		}
		passwordChange := runtimeMutableChange(passwordPath, encodedPassword, 0o600, manager, receipt)
		passwordChange.ExpectedPriorDigest = digestOf(passwordData)
		changes = append(changes, passwordChange)
	}

	encodedEntries, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("marshal WG-over-VK relay password entries: %w", err)
	}
	root["passwords"] = encodedEntries
	if _, ok := root["devices"]; ok {
		encodedDevices, err := json.Marshal(devices)
		if err != nil {
			return nil, fmt.Errorf("marshal WG-over-VK relay devices: %w", err)
		}
		root["devices"] = encodedDevices
	}
	encodedRoot, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal WG-over-VK relay passwords: %w", err)
	}
	encodedRoot = append(encodedRoot, '\n')
	relayChange := runtimeMutableChange(path, encodedRoot, 0o600, manager, receipt)
	relayChange.ExpectedPriorDigest = digestOf(data)
	markerPath := (deploy.Bot{DataDir: o.Layout.BotDataDir()}).WDTTReloadMarkerPath()
	markerChange := runtimeMutableChange(markerPath, []byte(botstate.Now()+"\n"), 0o644, manager, receipt)
	return append(changes, relayChange, markerChange), nil
}

func boundDevices(entry map[string]json.RawMessage) []string {
	var ids []string
	if id, _, err := relayString(entry, "device_id"); err == nil && id != "" && id != "multi" {
		ids = append(ids, id)
	}
	var list []string
	if raw, ok := entry["device_ids"]; ok && json.Unmarshal(raw, &list) == nil {
		ids = append(ids, list...)
	}
	return ids
}

// rotateSubscriptionTokens replaces each rotated user's subscription token.
// The token is the URL a client polls, so whoever holds a leaked one would
// otherwise be served the freshly minted credentials on the next poll. A new
// token carries no last_hash, which the bot's refresh loop seeds silently.
func (o Options) rotateSubscriptionTokens(manager *transaction.Manager, receipt transaction.Receipt, users map[string]bool) ([]transaction.Change, error) {
	path := filepath.Join(o.Layout.BotDataDir(), "wdtt", "subs.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the subscription registry: %w", err)
	}
	var subs map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &subs); err != nil {
		return nil, fmt.Errorf("parse the subscription registry %s: %w", path, err)
	}
	var owners []string
	for token, sub := range subs {
		uid, _, err := relayString(sub, "uid")
		if err != nil {
			return nil, fmt.Errorf("subscription registry entry: %w", err)
		}
		if users[uid] {
			delete(subs, token)
			if !slices.Contains(owners, uid) {
				owners = append(owners, uid)
			}
		}
	}
	if len(owners) == 0 {
		return nil, nil
	}
	slices.Sort(owners)
	for _, uid := range owners {
		token, err := botstate.NewToken()
		if err != nil {
			return nil, err
		}
		if _, taken := subs[token]; taken {
			return nil, fmt.Errorf("generated subscription token collides with an existing one")
		}
		entry := map[string]json.RawMessage{}
		for field, value := range map[string]string{"uid": uid, "created": botstate.Now()} {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			entry[field] = encoded
		}
		subs[token] = entry
	}
	encoded, err := json.Marshal(subs)
	if err != nil {
		return nil, fmt.Errorf("marshal the subscription registry: %w", err)
	}
	// 0644, matching the bot: the subscription server reads it.
	change := runtimeMutableChange(path, encoded, 0o644, manager, receipt)
	change.ExpectedPriorDigest = digestOf(data)
	return []transaction.Change{change}, nil
}

// cloneSecrets copies a credential set deeply enough that regeneration cannot
// mutate the snapshot the rotation is later proven against.
func cloneSecrets(in profile.Secrets) profile.Secrets {
	out := in
	out.Endpoints = make(map[profile.Protocol]profile.EndpointSecrets, len(in.Endpoints))
	for protocol, endpoint := range in.Endpoints {
		out.Endpoints[protocol] = endpoint
	}
	out.Users = make([]profile.UserSecrets, len(in.Users))
	for i, user := range in.Users {
		copied := user
		copied.Peers = make(map[profile.Protocol]profile.PeerSecrets, len(user.Peers))
		for protocol, peer := range user.Peers {
			copied.Peers[protocol] = peer
		}
		out.Users[i] = copied
	}
	return out
}
