package profile

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// ReassignSubnetPreserveHost returns a credential snapshot whose addresses for
// one WireGuard protocol use to while retaining each address's numeric host
// offset. It validates the complete move before changing the returned copy.
// Key material and every other protocol are left untouched.
func ReassignSubnetPreserveHost(secrets Secrets, protocol Protocol, from, to netip.Prefix) (Secrets, error) {
	if !protocol.IsWireGuard() {
		return Secrets{}, fmt.Errorf("protocol %q is not WireGuard", protocol)
	}
	if err := validateSubnetMove(from, to); err != nil {
		return Secrets{}, err
	}

	endpoint, ok := secrets.Endpoints[protocol]
	if !ok {
		return Secrets{}, fmt.Errorf("credentials contain no endpoint for %q", protocol)
	}
	movedEndpoint, err := reassignPrefixPreserveHost(endpoint.Address, from, to, to.Bits())
	if err != nil {
		return Secrets{}, fmt.Errorf("endpoint %q: %w", protocol, err)
	}

	movedPeers := make([]netip.Prefix, len(secrets.Users))
	seen := map[netip.Addr]string{movedEndpoint.Addr(): "endpoint"}
	for index, user := range secrets.Users {
		peer, present := user.Peers[protocol]
		if !present {
			continue
		}
		moved, moveErr := reassignPrefixPreserveHost(peer.Address, from, to, peer.Address.Bits())
		if moveErr != nil {
			return Secrets{}, fmt.Errorf("user %q peer %q: %w", user.Name, protocol, moveErr)
		}
		if owner, collision := seen[moved.Addr()]; collision {
			return Secrets{}, fmt.Errorf("user %q peer %q maps to %s already used by %s", user.Name, protocol, moved.Addr(), owner)
		}
		seen[moved.Addr()] = "user " + user.Name
		movedPeers[index] = moved
	}

	result := cloneSecretsForSubnetMove(secrets)
	endpoint.Address = movedEndpoint
	result.Endpoints[protocol] = endpoint
	for index := range result.Users {
		if !movedPeers[index].IsValid() {
			continue
		}
		peer := result.Users[index].Peers[protocol]
		peer.Address = movedPeers[index]
		result.Users[index].Peers[protocol] = peer
	}
	return result, nil
}

// ReassignAddressPreserveHost maps one IPv4 host address between prefixes.
// It is shared with runtime credential stores that are not profile.Secrets.
func ReassignAddressPreserveHost(address netip.Addr, from, to netip.Prefix) (netip.Addr, error) {
	if err := validateSubnetMove(from, to); err != nil {
		return netip.Addr{}, err
	}
	moved, err := reassignPrefixPreserveHost(netip.PrefixFrom(address, 32), from, to, 32)
	if err != nil {
		return netip.Addr{}, err
	}
	return moved.Addr(), nil
}

func validateSubnetMove(from, to netip.Prefix) error {
	if !from.IsValid() || !to.IsValid() || !from.Addr().Is4() || !to.Addr().Is4() {
		return fmt.Errorf("subnet migration requires valid IPv4 prefixes (from=%s to=%s)", from, to)
	}
	if from != from.Masked() || to != to.Masked() {
		return fmt.Errorf("subnet migration prefixes must be network prefixes (from=%s to=%s)", from, to)
	}
	return nil
}

func reassignPrefixPreserveHost(address netip.Prefix, from, to netip.Prefix, outputBits int) (netip.Prefix, error) {
	if !address.IsValid() || !address.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("address %s is not IPv4", address)
	}
	if !from.Contains(address.Addr()) {
		return netip.Prefix{}, fmt.Errorf("address %s is outside source subnet %s", address, from)
	}
	fromBase := ipv4Number(from.Addr())
	toBase := ipv4Number(to.Addr())
	offset := uint64(ipv4Number(address.Addr()) - fromBase)
	toHosts := uint64(1) << uint(32-to.Bits())
	if offset >= toHosts {
		return netip.Prefix{}, fmt.Errorf("host offset %d from %s does not fit in %s", offset, from, to)
	}
	// The generator reserves the network and broadcast addresses. Refusing a
	// move to either keeps a shrink from producing a syntactically valid but
	// unusable endpoint or peer.
	if offset == 0 || offset == toHosts-1 {
		return netip.Prefix{}, fmt.Errorf("host offset %d maps to a reserved address in %s", offset, to)
	}
	moved := numberIPv4(uint32(uint64(toBase) + offset))
	return netip.PrefixFrom(moved, outputBits), nil
}

func ipv4Number(address netip.Addr) uint32 {
	bytes := address.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

func numberIPv4(number uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], number)
	return netip.AddrFrom4(bytes)
}

func cloneSecretsForSubnetMove(secrets Secrets) Secrets {
	result := secrets
	result.Endpoints = make(map[Protocol]EndpointSecrets, len(secrets.Endpoints))
	for protocol, endpoint := range secrets.Endpoints {
		result.Endpoints[protocol] = endpoint
	}
	result.Users = append([]UserSecrets(nil), secrets.Users...)
	for index := range result.Users {
		result.Users[index].Peers = make(map[Protocol]PeerSecrets, len(secrets.Users[index].Peers))
		for protocol, peer := range secrets.Users[index].Peers {
			result.Users[index].Peers[protocol] = peer
		}
	}
	return result
}
