package apply

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	botstate "github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// migrateSubnets prepares every bootstrap-visible credential copy before the
// file transaction: server config, client handover, bot peers, the external
// WG-over-VK relay's passwords.json and subscription-cache invalidation.
func (o Options) migrateSubnets(runtime *runtimeState, manager *transaction.Manager, migrations map[profile.Protocol]state.SubnetMigration) ([]byte, []transaction.Change, error) {
	botPeers, err := o.readBotPeers()
	if err != nil {
		return nil, nil, err
	}
	if err := verifyClientPeerCopies(runtime.credentials, runtime.handover, botPeers, migrations); err != nil {
		return nil, nil, fmt.Errorf("subnet migration is blocked because client credential copies are incomplete: %w", err)
	}

	protocols := make([]profile.Protocol, 0, len(migrations))
	for protocol := range migrations {
		protocols = append(protocols, protocol)
	}
	sort.Slice(protocols, func(i, j int) bool { return protocols[i] < protocols[j] })

	server := runtime.credentials
	handover := runtime.handover
	botChanges := []transaction.Change{}
	receipt, _, err := manager.Current()
	if err != nil {
		return nil, nil, fmt.Errorf("read bot-state ownership: %w", err)
	}
	for _, protocol := range protocols {
		migration := migrations[protocol]
		from := netip.MustParsePrefix(migration.From)
		to := netip.MustParsePrefix(migration.To)
		server, err = profile.ReassignSubnetPreserveHost(server, protocol, from, to)
		if err != nil {
			return nil, nil, fmt.Errorf("validate live %s subnet migration: %w", protocol, err)
		}
		if _, exists := handover.Endpoints[protocol]; exists {
			handover, err = profile.ReassignSubnetPreserveHost(handover, protocol, from, to)
			if err != nil {
				return nil, nil, fmt.Errorf("validate client %s subnet migration: %w", protocol, err)
			}
		}
		for _, peer := range botPeers {
			if peer.protocol != protocol {
				continue
			}
			moved, moveErr := profile.ReassignAddressPreserveHost(peer.addr, from, to)
			if moveErr != nil {
				return nil, nil, fmt.Errorf("migrate bot peer %s: %w", peer.path, moveErr)
			}
			// Bare IPv4 address, matching provision.NextIP: the bot's client
			// renderers append "/32" themselves when building WireGuard nodes.
			peer.value.IP = moved.String()
			encoded, marshalErr := json.Marshal(peer.value)
			if marshalErr != nil {
				return nil, nil, marshalErr
			}
			change := transaction.Change{Path: peer.path, Data: encoded, Mode: 0o600, UID: manager.UID, GID: manager.GID, Ownership: transaction.RuntimeMutable}
			if owned, ok := receipt.Files[peer.path]; ok && owned.Ownership == transaction.RuntimeMutable {
				change.ReplaceRuntimeMutable = true
			} else {
				change.AdoptRuntimeMutable = true
			}
			botChanges = append(botChanges, change)
		}
		if protocol == profile.WGWDTT {
			relayChanges, relayErr := o.wdttRelayChanges(manager, receipt, botPeers, from, to)
			if relayErr != nil {
				return nil, nil, relayErr
			}
			botChanges = append(botChanges, relayChanges...)
		}
	}
	cacheChanges, err := o.subscriptionCacheChanges(manager, receipt)
	if err != nil {
		return nil, nil, err
	}
	botChanges = append(botChanges, cacheChanges...)
	runtime.credentials = server
	runtime.handover = handover
	data, err := json.MarshalIndent(handover, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal migrated client credentials: %w", err)
	}
	data = append(data, '\n')
	runtime.expectedSecretsDigest = digestOf(data)
	return data, botChanges, nil
}

func (o Options) wdttRelayChanges(manager *transaction.Manager, receipt transaction.Receipt, peers []botPeerFile, from, to netip.Prefix) ([]transaction.Change, error) {
	var wdttPeers []botPeerFile
	for _, peer := range peers {
		if peer.protocol == profile.WGWDTT {
			wdttPeers = append(wdttPeers, peer)
		}
	}
	if len(wdttPeers) == 0 {
		return nil, nil
	}
	configDir := o.Desired.Bot.WDTTConfigDirectory
	if configDir == "" {
		return nil, fmt.Errorf("subnet migration for %s is blocked: bot.wdttConfigDirectory does not name the external relay config directory", profile.WGWDTT)
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
	rawEntries, ok := root["passwords"]
	if !ok || json.Unmarshal(rawEntries, &entries) != nil || entries == nil {
		return nil, fmt.Errorf("parse WG-over-VK relay passwords %s: passwords must be an object", path)
	}

	expected := make(map[string]botPeerFile, len(wdttPeers))
	for _, peer := range wdttPeers {
		passwordPath := filepath.Join(o.Layout.BotDataDir(), "wdtt", peer.uid+".json")
		passwordData, readErr := os.ReadFile(passwordPath)
		if readErr != nil {
			return nil, fmt.Errorf("read WG-over-VK password copy for peer %s: %w", peer.path, readErr)
		}
		var saved botstate.WDTTPassword
		if json.Unmarshal(passwordData, &saved) != nil || saved.Password == "" {
			return nil, fmt.Errorf("invalid WG-over-VK password copy %s", passwordPath)
		}
		if _, duplicate := expected[saved.Password]; duplicate {
			return nil, fmt.Errorf("multiple WG-over-VK bot peers share one relay password")
		}
		expected[saved.Password] = peer
	}

	migrated := make(map[string]bool, len(expected))
	for password, entry := range entries {
		wgIP, hasIP, decodeErr := relayString(entry, "wg_ip")
		if decodeErr != nil {
			return nil, fmt.Errorf("WG-over-VK relay entry: %w", decodeErr)
		}
		wgPriv, hasPriv, decodeErr := relayString(entry, "wg_priv")
		if decodeErr != nil {
			return nil, fmt.Errorf("WG-over-VK relay entry: %w", decodeErr)
		}
		if !hasIP && !hasPriv {
			continue
		}
		if !hasIP || !hasPriv || wgIP == "" || wgPriv == "" {
			return nil, fmt.Errorf("WG-over-VK relay entry has an incomplete wg_ip/wg_priv pair")
		}
		addr, parseErr := netip.ParseAddr(wgIP)
		if parseErr != nil || !addr.Is4() {
			return nil, fmt.Errorf("WG-over-VK relay entry has invalid bare IPv4 wg_ip %q", wgIP)
		}
		if !from.Contains(addr) {
			continue
		}
		peer, exists := expected[password]
		if !exists {
			return nil, fmt.Errorf("WG-over-VK relay entry has wg_ip %s in the migrating subnet but no matching bot peer", wgIP)
		}
		if peer.addr != addr || peer.value.Priv != wgPriv {
			return nil, fmt.Errorf("WG-over-VK relay entry does not match bot peer %s", peer.path)
		}
		moved, moveErr := profile.ReassignAddressPreserveHost(addr, from, to)
		if moveErr != nil {
			return nil, fmt.Errorf("migrate relay entry for bot peer %s: %w", peer.path, moveErr)
		}
		encoded, marshalErr := json.Marshal(moved.String())
		if marshalErr != nil {
			return nil, marshalErr
		}
		entry["wg_ip"] = encoded
		migrated[password] = true
	}
	for password, peer := range expected {
		if !migrated[password] {
			return nil, fmt.Errorf("bot peer %s has no matching relay passwords.json entry", peer.path)
		}
	}

	encodedEntries, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("marshal WG-over-VK relay password entries: %w", err)
	}
	root["passwords"] = encodedEntries
	encodedRoot, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal WG-over-VK relay passwords: %w", err)
	}
	encodedRoot = append(encodedRoot, '\n')

	relayChange := runtimeMutableChange(path, encodedRoot, 0o600, manager, receipt)
	relayChange.ExpectedPriorDigest = digestOf(data)
	markerPath := (deploy.Bot{DataDir: o.Layout.BotDataDir()}).WDTTReloadMarkerPath()
	markerChange := runtimeMutableChange(markerPath, []byte(botstate.Now()+"\n"), 0o644, manager, receipt)
	return []transaction.Change{relayChange, markerChange}, nil
}

func relayString(entry map[string]json.RawMessage, field string) (string, bool, error) {
	raw, ok := entry[field]
	if !ok {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("%s must be a string", field)
	}
	return value, true, nil
}

func runtimeMutableChange(path string, data []byte, mode os.FileMode, manager *transaction.Manager, receipt transaction.Receipt) transaction.Change {
	change := transaction.Change{Path: path, Data: data, Mode: mode, UID: manager.UID, GID: manager.GID, Ownership: transaction.RuntimeMutable}
	if owned, ok := receipt.Files[path]; ok && owned.Ownership == transaction.RuntimeMutable {
		change.ReplaceRuntimeMutable = true
	} else if _, err := os.Lstat(path); err == nil {
		change.AdoptRuntimeMutable = true
	}
	return change
}

type botPeerFile struct {
	path, uid string
	protocol  profile.Protocol
	addr      netip.Addr
	value     botstate.Peer
}

func (o Options) readBotPeers() ([]botPeerFile, error) {
	dir := filepath.Join(o.Layout.BotDataDir(), "awg")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect bot peer state: %w", err)
	}
	var out []botPeerFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, fmt.Errorf("unexpected bot peer entry %s", filepath.Join(dir, entry.Name()))
		}
		base := strings.TrimSuffix(entry.Name(), ".json")
		protocol, uid := profile.AWG2, base
		for _, candidate := range []profile.Protocol{profile.AWG3, profile.WGMasque, profile.WGWDTT} {
			suffix := "-" + string(candidate)
			if strings.HasSuffix(base, suffix) {
				protocol, uid = candidate, strings.TrimSuffix(base, suffix)
				break
			}
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		var peer botstate.Peer
		if json.Unmarshal(data, &peer) != nil || uid == "" || uid == "." || uid == ".." || peer.Priv == "" || peer.Pub == "" || peer.IP == "" {
			return nil, fmt.Errorf("invalid bot peer file %s", path)
		}
		addr, addrErr := netip.ParseAddr(peer.IP)
		if addrErr != nil || !addr.Is4() {
			return nil, fmt.Errorf("invalid bot peer address in %s: want bare IPv4 address, got %q", path, peer.IP)
		}
		out = append(out, botPeerFile{path: path, uid: uid, protocol: protocol, addr: addr, value: peer})
	}
	return out, nil
}

func verifyClientPeerCopies(live, handover profile.Secrets, botPeers []botPeerFile, migrations map[profile.Protocol]state.SubnetMigration) error {
	liveByName := make(map[string]profile.UserSecrets, len(live.Users))
	for _, user := range live.Users {
		liveByName[user.Name] = user
	}
	for _, bot := range botPeers {
		if _, selected := migrations[bot.protocol]; !selected {
			continue
		}
		user, ok := liveByName[bot.uid]
		peer, peerOK := user.Peers[bot.protocol]
		if !ok || !peerOK || peer.PublicKey != bot.value.Pub || peer.Address != netip.PrefixFrom(bot.addr, 32) {
			return fmt.Errorf("bot peer %s has no matching live peer", bot.path)
		}
	}
	byName := make(map[string]profile.UserSecrets, len(handover.Users))
	for _, user := range handover.Users {
		byName[user.Name] = user
	}
	for _, liveUser := range live.Users {
		clientUser := byName[liveUser.Name]
		for protocol := range migrations {
			livePeer, exists := liveUser.Peers[protocol]
			if !exists {
				continue
			}
			clientPeer, ok := clientUser.Peers[protocol]
			if ok && clientPeer.PublicKey == livePeer.PublicKey && clientPeer.Address == livePeer.Address {
				continue
			}
			covered := false
			for _, bot := range botPeers {
				if bot.uid == liveUser.Name && bot.protocol == protocol && bot.value.Pub == livePeer.PublicKey && netip.PrefixFrom(bot.addr, 32) == livePeer.Address {
					covered = true
					break
				}
			}
			if !covered {
				return fmt.Errorf("live user %q peer %q has no matching secrets.json or bot copy", liveUser.Name, protocol)
			}
		}
	}
	for protocol, liveEndpoint := range live.Endpoints {
		clientEndpoint, ok := handover.Endpoints[protocol]
		if !ok || clientEndpoint.PrivateKey != liveEndpoint.PrivateKey || clientEndpoint.PublicKey != liveEndpoint.PublicKey || clientEndpoint.Address != liveEndpoint.Address {
			return fmt.Errorf("live endpoint %q does not match secrets.json", protocol)
		}
	}
	return nil
}

func (o Options) subscriptionCacheChanges(manager *transaction.Manager, receipt transaction.Receipt) ([]transaction.Change, error) {
	paths, err := filepath.Glob(filepath.Join(o.Layout.BotDataDir(), "wdtt", "subs-cache", "*.json"))
	if err != nil {
		return nil, err
	}
	changes := make([]transaction.Change, 0, len(paths))
	for _, path := range paths {
		change := transaction.Change{Path: path, Delete: true, Ownership: transaction.RuntimeMutable}
		if _, ok := receipt.Files[path]; !ok {
			change.AdoptRuntimeMutable = true
		}
		changes = append(changes, change)
	}
	return changes, nil
}
