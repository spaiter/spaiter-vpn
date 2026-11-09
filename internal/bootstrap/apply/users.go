package apply

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// prepareSeedUserMigration validates the live and handover user sets against an
// authorized seedUsers migration policy, merges handover private keys into the
// preserved credential set for kept seed users, removes retired seed users, and
// returns the ordered target user list (desired seedUsers followed by live
// bot-provisioned users) plus any subscription-cache invalidation changes.
func (o Options) prepareSeedUserMigration(runtime *runtimeState, policy state.SeedUsersMigration, manager *transaction.Manager, cacheAlreadyInvalidated bool) ([]string, []transaction.Change, error) {
	handoverNames := runtime.handover.Names()
	if !slices.Equal(handoverNames, policy.From) {
		return nil, nil, fmt.Errorf("seedUsers migration is blocked: secrets.json lists %v, not migrationPolicy.seedUsers.from %v", handoverNames, policy.From)
	}

	botPeers, err := o.readBotPeers()
	if err != nil {
		return nil, nil, err
	}
	fromSet := make(map[string]bool, len(policy.From))
	for _, name := range policy.From {
		fromSet[name] = true
	}
	toSet := make(map[string]bool, len(policy.To))
	for _, name := range policy.To {
		toSet[name] = true
	}
	for _, peer := range botPeers {
		if fromSet[peer.uid] || toSet[peer.uid] {
			return nil, nil, fmt.Errorf("seedUsers migration is blocked: user %q has bot-managed peer state in %s", peer.uid, peer.path)
		}
	}

	liveByName := make(map[string]profile.UserSecrets, len(runtime.credentials.Users))
	for _, user := range runtime.credentials.Users {
		liveByName[user.Name] = user
	}

	mergedSeedByName := make(map[string]profile.UserSecrets, len(runtime.handover.Users))
	for _, handoverUser := range runtime.handover.Users {
		liveUser, ok := liveByName[handoverUser.Name]
		if !ok {
			return nil, nil, fmt.Errorf("seedUsers migration is blocked: seed user %q from secrets.json is missing in live config.json", handoverUser.Name)
		}
		merged, err := mergeSeedUserSecrets(liveUser, handoverUser)
		if err != nil {
			return nil, nil, err
		}
		mergedSeedByName[handoverUser.Name] = merged
	}

	var botUsers []string
	for _, liveUser := range runtime.credentials.Users {
		if fromSet[liveUser.Name] {
			continue
		}
		if toSet[liveUser.Name] {
			return nil, nil, fmt.Errorf("seedUsers migration is blocked: added seed user %q already exists in live config.json", liveUser.Name)
		}
		botUsers = append(botUsers, liveUser.Name)
	}

	keptCredentials := make([]profile.UserSecrets, 0, len(runtime.credentials.Users))
	for _, liveUser := range runtime.credentials.Users {
		if fromSet[liveUser.Name] {
			if !toSet[liveUser.Name] {
				// Retired seed user: drop from preserved credentials so its
				// WireGuard peer addresses are released and its credentials are
				// removed from the re-rendered config.json.
				continue
			}
			keptCredentials = append(keptCredentials, mergedSeedByName[liveUser.Name])
			continue
		}
		keptCredentials = append(keptCredentials, liveUser)
	}
	runtime.credentials.Users = keptCredentials

	targetUsers := make([]string, 0, len(policy.To)+len(botUsers))
	targetUsers = append(targetUsers, policy.To...)
	targetUsers = append(targetUsers, botUsers...)

	removedAny := false
	for _, name := range policy.From {
		if !toSet[name] {
			removedAny = true
			break
		}
	}
	var extraChanges []transaction.Change
	if removedAny && !cacheAlreadyInvalidated {
		receipt, _, err := manager.Current()
		if err != nil {
			return nil, nil, fmt.Errorf("read bot-state ownership: %w", err)
		}
		extraChanges, err = o.subscriptionCacheChanges(manager, receipt)
		if err != nil {
			return nil, nil, err
		}
	}
	return targetUsers, extraChanges, nil
}

func mergeSeedUserSecrets(live, handover profile.UserSecrets) (profile.UserSecrets, error) {
	checkString := func(protocol string, liveVal, handoverVal string) error {
		if liveVal != "" && liveVal != handoverVal {
			return fmt.Errorf("seedUsers migration is blocked: seed user %q %s credential in config.json does not match secrets.json", live.Name, protocol)
		}
		return nil
	}
	for _, check := range []struct {
		protocol string
		live     string
		handover string
	}{
		{"vless-reality", live.VLESSRealityUUID, handover.VLESSRealityUUID},
		{"vless-ws-cdn", live.VLESSWSCDNUUID, handover.VLESSWSCDNUUID},
		{"shadowtls", live.ShadowTLSPassword, handover.ShadowTLSPassword},
		{"snell", live.SnellUserKey, handover.SnellUserKey},
		{"mieru", live.MieruPassword, handover.MieruPassword},
		{"hysteria2", live.Hysteria2Password, handover.Hysteria2Password},
		{"tuic-uuid", live.TUICUUID, handover.TUICUUID},
		{"tuic-password", live.TUICPassword, handover.TUICPassword},
		{"anytls", live.AnyTLSPassword, handover.AnyTLSPassword},
		{"naive", live.NaivePassword, handover.NaivePassword},
		{"vless-xhttp", live.VLESSXHTTPUUID, handover.VLESSXHTTPUUID},
	} {
		if err := checkString(check.protocol, check.live, check.handover); err != nil {
			return profile.UserSecrets{}, err
		}
	}

	merged := handover
	merged.Peers = make(map[profile.Protocol]profile.PeerSecrets, len(handover.Peers)+len(live.Peers))
	for protocol, peer := range handover.Peers {
		merged.Peers[protocol] = peer
	}
	for protocol, livePeer := range live.Peers {
		handoverPeer, ok := handover.Peers[protocol]
		if !ok || handoverPeer.PrivateKey == "" || handoverPeer.PublicKey != livePeer.PublicKey || handoverPeer.Address != livePeer.Address {
			return profile.UserSecrets{}, fmt.Errorf("seedUsers migration is blocked: seed user %q peer %q in config.json does not match secrets.json", live.Name, protocol)
		}
		merged.Peers[protocol] = handoverPeer
	}
	return merged, nil
}

func finishSeedUserMigration(runtime *runtimeState, regenerated profile.Secrets, policy state.SeedUsersMigration) ([]byte, error) {
	byName := make(map[string]profile.UserSecrets, len(regenerated.Users))
	for _, user := range regenerated.Users {
		byName[user.Name] = user
	}
	handover := runtime.handover
	handover.Users = make([]profile.UserSecrets, 0, len(policy.To))
	for _, name := range policy.To {
		user, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("regenerated bundle is missing seed user %q", name)
		}
		handover.Users = append(handover.Users, user)
	}
	data, err := json.MarshalIndent(handover, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal migrated seedUsers credentials: %w", err)
	}
	data = append(data, '\n')
	runtime.handover = handover
	runtime.expectedSecretsDigest = digestOf(data)
	return data, nil
}

// refreshHandover brings secrets.json up to what a migration rendered, without
// changing anything a client already holds. The deployment facts (ports,
// handshakes) are replaced, because `clients` renders links from them and a
// moved port would otherwise be handed out at its old number. A slot or peer
// the migration minted for a seed user, such as a newly enabled protocol or a
// per-user MTProto secret, is added; it existed only on the server before,
// which is a credential no client could ever be given. Existing values are
// kept, and one that disagrees with the rendered bundle is refused.
func refreshHandover(handover, rendered profile.Secrets) (profile.Secrets, error) {
	out := handover
	out.Deployment = rendered.Deployment
	out.TierB.Facts = rendered.TierB.Facts
	// The shared MTProto secret is deployment-wide and may be retired.
	out.MTProto = rendered.MTProto
	if out.Reality.PrivateKey == "" {
		out.Reality = rendered.Reality
	}
	if out.Shadowsocks.Password == "" {
		out.Shadowsocks = rendered.Shadowsocks
	}
	if out.Snell.PSK == "" {
		out.Snell = rendered.Snell
	}
	if out.TierB.Hysteria2ObfsPassword == "" {
		out.TierB.Hysteria2ObfsPassword, out.TierB.Hysteria2ObfsType = rendered.TierB.Hysteria2ObfsPassword, rendered.TierB.Hysteria2ObfsType
	}
	if out.TierB.XHTTPReality.PrivateKey == "" {
		out.TierB.XHTTPReality = rendered.TierB.XHTTPReality
	}
	out.Endpoints = make(map[profile.Protocol]profile.EndpointSecrets, len(handover.Endpoints))
	for protocol, endpoint := range handover.Endpoints {
		out.Endpoints[protocol] = endpoint
	}
	for protocol, endpoint := range rendered.Endpoints {
		if _, ok := out.Endpoints[protocol]; !ok {
			out.Endpoints[protocol] = endpoint
		}
	}
	byName := make(map[string]profile.UserSecrets, len(rendered.Users))
	for _, user := range rendered.Users {
		byName[user.Name] = user
	}
	out.Users = make([]profile.UserSecrets, len(handover.Users))
	for i, user := range handover.Users {
		minted, ok := byName[user.Name]
		if !ok {
			out.Users[i] = user
			continue
		}
		filled, err := fillUserSlots(user, minted)
		if err != nil {
			return profile.Secrets{}, err
		}
		out.Users[i] = filled
	}
	return out, nil
}

func fillUserSlots(have, minted profile.UserSecrets) (profile.UserSecrets, error) {
	out := have
	for _, field := range []struct {
		slot string
		dst  *string
		src  string
	}{
		{profile.SlotVLESSReality, &out.VLESSRealityUUID, minted.VLESSRealityUUID},
		{profile.SlotVLESSWSCDN, &out.VLESSWSCDNUUID, minted.VLESSWSCDNUUID},
		{profile.SlotShadowTLS, &out.ShadowTLSPassword, minted.ShadowTLSPassword},
		{profile.SlotSnell, &out.SnellUserKey, minted.SnellUserKey},
		{profile.SlotMieru, &out.MieruPassword, minted.MieruPassword},
		{profile.SlotHysteria2, &out.Hysteria2Password, minted.Hysteria2Password},
		{profile.SlotTUIC, &out.TUICUUID, minted.TUICUUID},
		{profile.SlotTUIC, &out.TUICPassword, minted.TUICPassword},
		{profile.SlotAnyTLS, &out.AnyTLSPassword, minted.AnyTLSPassword},
		{profile.SlotNaive, &out.NaivePassword, minted.NaivePassword},
		{profile.SlotVLESSXHTTP, &out.VLESSXHTTPUUID, minted.VLESSXHTTPUUID},
		{profile.SlotMTProto, &out.MTProtoSecret, minted.MTProtoSecret},
	} {
		switch {
		case field.slot == profile.SlotMTProto:
			// Reissued when the front domain changes and dropped when the
			// mode is off, so the rendered value always wins.
			*field.dst = field.src
		case *field.dst == "":
			*field.dst = field.src
		case field.src != "" && *field.dst != field.src:
			return profile.UserSecrets{}, fmt.Errorf("seed user %q %s in secrets.json disagrees with the live configuration", have.Name, field.slot)
		}
	}
	out.Peers = make(map[profile.Protocol]profile.PeerSecrets, len(have.Peers))
	for protocol, peer := range have.Peers {
		out.Peers[protocol] = peer
	}
	for protocol, peer := range minted.Peers {
		if _, ok := out.Peers[protocol]; !ok && peer.PrivateKey != "" {
			out.Peers[protocol] = peer
		}
	}
	return out, nil
}
