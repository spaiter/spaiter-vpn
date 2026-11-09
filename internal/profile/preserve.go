package profile

import (
	"fmt"
	"net/netip"
)

// Regenerate renders a configuration for a new shape without reissuing any
// credential that already exists.
//
// This is what makes a migration possible at all. Changing a port, enabling a
// protocol or raising the log level means producing a new config.json — and
// calling Generate for that would mint a new Reality keypair, new per-user
// UUIDs and a new clash secret, which does not "update" a deployment so much
// as replace it with one none of its clients can reach. Here every key, every
// password and every peer address that is already in use is carried over, and
// only genuinely new material is minted: a protocol that was off, or a user
// who did not exist.
//
// What it does NOT do is decide what should change. It renders the spec it is
// given; the caller is responsible for having refused the changes that cannot
// be made safely.
func Regenerate(spec Spec, existing Secrets) (*Bundle, error) {
	return generate(spec, &existing)
}

// reuseOrMint keeps an already-issued credential and mints one only when the
// slot is empty.
//
// Taking a pointer to the slot rather than returning a value to assign is
// deliberate: it makes "record what was issued" and "decide whether to issue"
// the same step, so a site cannot preserve the credential and then forget to
// write it back — which would hand the client a key the server does not know.
func reuseOrMint(slot *string, what string, mint func() (string, error)) (string, error) {
	if *slot != "" {
		return *slot, nil
	}
	value, err := mint()
	if err != nil {
		return "", fmt.Errorf("generate %s: %w", what, err)
	}
	*slot = value
	return value, nil
}

// user finds a previously issued credential set by name.
func (s *Secrets) user(name string) (UserSecrets, bool) {
	if s == nil {
		return UserSecrets{}, false
	}
	for _, candidate := range s.Users {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return UserSecrets{}, false
}

// clone copies a credential set deeply enough that generation cannot mutate
// the bundle it was preserved from.
func (u UserSecrets) clone() UserSecrets {
	out := u
	out.Peers = make(map[Protocol]PeerSecrets, len(u.Peers))
	for protocol, peer := range u.Peers {
		out.Peers[protocol] = peer
	}
	return out
}

// allocatePeerAddress returns the address a user's peer should have on an
// endpoint: the one it already has, or the lowest free host in the subnet.
//
// Not the user's index in the list, which is what a fresh generation can afford
// to use. Once credentials are preserved the two diverge the moment a user is
// removed: every later user's index shifts, so an index-derived address would
// silently reassign addresses that are already in clients' configs — and two
// users can end up on one address, which the endpoint then refuses to start
// with.
func allocatePeerAddress(prefix netip.Prefix, existing PeerSecrets, taken map[netip.Addr]bool) (netip.Prefix, error) {
	if existing.Address.IsValid() {
		if !prefix.Contains(existing.Address.Addr()) {
			return netip.Prefix{}, fmt.Errorf("preserved peer address %s is outside the endpoint subnet %s; a subnet change is a migration that has to reassign peers deliberately", existing.Address, prefix)
		}
		taken[existing.Address.Addr()] = true
		return existing.Address, nil
	}
	// Host 1 is the endpoint's own address.
	for offset := 2; offset < 1<<16; offset++ {
		candidate, err := hostInPrefix(prefix, offset)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("no free address left in %s: %w", prefix, err)
		}
		if taken[candidate.Addr()] {
			continue
		}
		taken[candidate.Addr()] = true
		return netip.PrefixFrom(candidate.Addr(), 32), nil
	}
	return netip.Prefix{}, fmt.Errorf("no free address left in %s", prefix)
}
