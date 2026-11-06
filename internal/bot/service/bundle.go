package service

import (
	"context"
	"fmt"
	"slices"

	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Bundle renders the all-methods subscription for one user.
//
// With provision set, anything the user is missing is created and the whole run
// costs one apply. Without it nothing on the server is touched and a method the
// user has never asked for is simply absent -- that is the mode the refresh
// loop and the HTTP handler use, and creating accounts from a timer would grow
// the config for someone who pressed nothing.
func (s *Service) Bundle(ctx context.Context, uid string, provision bool) ([]byte, error) {
	if provision {
		var done func()
		ctx, done = s.batch.Begin(ctx)
		defer done()
	}

	nodes, err := s.bundleNodes(ctx, uid, provision)
	if err != nil {
		return nil, err
	}
	return clientcfg.Assemble(s.cfg, nodes).Marshal()
}

// bundleNodes builds one node per method the user has.
//
// The distinction running through this is between a method the user does not
// have yet and a method that is broken. The first is skipped silently; the
// second is an error.
//
// bot.py collapsed the two -- every builder was wrapped in a bare except that
// logged and dropped the node -- so a generator broken by a schema change
// produced a shorter bundle that looked perfectly healthy, and the only symptom
// was a protocol quietly disappearing from everyone's client.
func (s *Service) bundleNodes(ctx context.Context, uid string, provision bool) ([]any, error) {
	inbounds, err := s.UserInbounds(ctx)
	if err != nil {
		return nil, err
	}

	var nodes []any
	for _, ref := range inbounds {
		if slices.Contains(s.cfg.Bundle.SkipTags, ref.Tag) {
			continue
		}

		var inbound clientcfg.Inbound
		var user clientcfg.User
		if provision {
			account, err := s.prov.EnsureUser(ctx, ref.Tag, uid)
			if err != nil {
				return nil, err
			}
			if inbound, err = clientcfg.ParseInbound(account.Inbound); err != nil {
				return nil, fmt.Errorf("service: parse inbound %s: %w", ref.Tag, err)
			}
			if user, err = clientcfg.ParseUser(account.User); err != nil {
				return nil, fmt.Errorf("service: parse user on %s: %w", ref.Tag, err)
			}
		} else {
			if inbound, err = s.inbound(ctx, ref.Tag); err != nil {
				return nil, err
			}
			var found bool
			if user, found, err = s.existingUser(ctx, ref.Tag, uid); err != nil {
				return nil, err
			}
			if !found {
				continue // the user has no account here, which is not a fault
			}
		}

		node, err := clientcfg.BundleNode(s.cfg, inbound, user, s.Label(inbound))
		if err != nil {
			return nil, fmt.Errorf("service: build the %s node: %w", ref.Tag, err)
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}

	special, err := s.specialNodes(ctx, uid, provision)
	if err != nil {
		return nil, err
	}
	return append(nodes, special...), nil
}

// specialNodes are the methods that are not a plain inbound: the WireGuard
// endpoints and the two chains.
func (s *Service) specialNodes(ctx context.Context, uid string, provision bool) ([]any, error) {
	var nodes []any

	awg, ok, err := s.awgNode(ctx, s.cfg.Tags.AWG, uid, provision)
	if err != nil {
		return nil, err
	}
	if ok {
		nodes = append(nodes, awg)
	}

	// AmneziaWG 3.1 is gated, and the gate is not caution for its own sake: a
	// core built before the 3.x options landed rejects the WHOLE subscription
	// with `unknown field "header_protection_key"` rather than skipping the
	// node, because the top-level config is decoded with unknown fields
	// disallowed. One old client turns this into no configuration at all.
	if s.cfg.Bundle.EnableAWG3 {
		awg3, ok, err := s.awgNode(ctx, s.cfg.Tags.AWG3, uid, provision)
		if err != nil {
			return nil, err
		}
		if ok {
			nodes = append(nodes, awg3)
		}
	}

	masque, ok, err := s.masqueNode(ctx, uid, provision)
	if err != nil {
		return nil, err
	}
	if ok {
		nodes = append(nodes, masque)
	}

	wdtt, ok, err := s.wdttNode(ctx, uid, provision)
	if err != nil {
		return nil, err
	}
	if ok {
		nodes = append(nodes, wdtt)
	}

	// Chains are gated too: an unknown "chain" outbound breaks the url-test
	// group on a core that cannot expand it, which costs the user every fast
	// method rather than just these two.
	if s.cfg.Bundle.EnableChains {
		chains, err := s.chainNodes(ctx, uid, provision)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, chains...)
	}
	return nodes, nil
}

// peerFor returns the user's peer on an endpoint, provisioning only if asked.
func (s *Service) peerFor(ctx context.Context, tag, uid string, provision bool) (state.Peer, clientcfg.Endpoint, bool, error) {
	if provision {
		peer, err := s.prov.EnsurePeer(ctx, tag, uid)
		if err != nil {
			return state.Peer{}, clientcfg.Endpoint{}, false, err
		}
		endpoint, err := s.endpoint(ctx, tag)
		if err != nil {
			return state.Peer{}, clientcfg.Endpoint{}, false, err
		}
		return state.Peer{Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: peer.Address},
			endpoint, true, nil
	}

	saved, found, err := s.store.Peer(uid, tag)
	if err != nil || !found {
		return state.Peer{}, clientcfg.Endpoint{}, false, err
	}
	endpoint, err := s.endpoint(ctx, tag)
	if err != nil {
		return state.Peer{}, clientcfg.Endpoint{}, false, err
	}
	return saved, endpoint, true, nil
}

func (s *Service) awgNode(ctx context.Context, tag, uid string, provision bool) (any, bool, error) {
	peer, endpoint, ok, err := s.peerFor(ctx, tag, uid, provision)
	if err != nil || !ok {
		return nil, false, err
	}
	// The UDP host, not the proxy one: a WireGuard peer handed a dual-stack
	// name resolves to AAAA first and never handshakes.
	node, err := clientcfg.AWGNode(endpoint, peer, s.endpointLabel(tag), s.udpHost())
	if err != nil {
		return nil, false, fmt.Errorf("service: build the %s node: %w", tag, err)
	}
	return node, true, nil
}

func (s *Service) masqueNode(ctx context.Context, uid string, provision bool) (any, bool, error) {
	tag := s.cfg.Tags.MASQUEWG
	peer, endpoint, ok, err := s.peerFor(ctx, tag, uid, provision)
	if err != nil || !ok {
		return nil, false, err
	}
	node, err := clientcfg.MASQUEWGNode(s.cfg, endpoint, peer,
		s.cfg.MASQUEWG.Port, s.cfg.MASQUEWG.Path)
	if err != nil {
		return nil, false, fmt.Errorf("service: build the masque-wg node: %w", err)
	}
	return node, true, nil
}

func (s *Service) wdttNode(ctx context.Context, uid string, provision bool) (any, bool, error) {
	var password string
	if provision {
		wdtt, err := s.prov.EnsureWDTT(ctx, s.cfg.WDTT.Tag, uid, s.relayPasswordsPath())
		if err != nil {
			return nil, false, err
		}
		password = wdtt.Password
	} else {
		saved, found, err := s.store.WDTTPassword(uid)
		if err != nil || !found {
			return nil, false, err
		}
		password = saved
	}

	hashes, err := s.store.LiveVKHashes(s.cfg.WDTT.Hashes)
	if err != nil {
		return nil, false, err
	}
	return clientcfg.WDTTNode(s.cfg, password, hashes), true, nil
}

// chainNodes builds the two multi-leg methods.
//
// Both are skipped rather than failed when the user has nothing yet -- no WARP
// account registered, no shadowtls account -- for the same reason as the rest:
// a refresh must not mint anything.
func (s *Service) chainNodes(ctx context.Context, uid string, provision bool) ([]any, error) {
	var nodes []any

	stlsTag := s.cfg.Tags.ShadowTLS
	stls, err := s.inbound(ctx, stlsTag)
	if err == nil && stls.Detour != "" {
		backend, err := s.inbound(ctx, stls.Detour)
		if err != nil {
			return nil, err
		}
		user, found, err := s.chainUser(ctx, stlsTag, uid, provision)
		if err != nil {
			return nil, err
		}
		if found {
			nodes = append(nodes, clientcfg.ShadowTLSChain(s.cfg, stls, backend, user,
				s.cfg.NodeTags.ShadowTLS))
		}
	}

	account, found, err := s.store.WARPAccount(uid)
	if err != nil {
		return nil, err
	}
	if !found && provision {
		if account, err = s.prov.EnsureWARP(ctx, uid, s.registrar); err != nil {
			// Registration reaches Cloudflare and can fail for reasons that
			// have nothing to do with this user. One method missing from the
			// bundle is better than no bundle at all, so this is reported and
			// skipped rather than fatal.
			s.log.Warn("no WARP node in the bundle: registration failed",
				"uid", uid, "error", err)
			return nodes, nil
		}
		found = true
	}
	if !found {
		return nodes, nil
	}

	inner, found, err := s.chainUser(ctx, s.cfg.WARP.InnerTag, uid, provision)
	if err != nil || !found {
		return nodes, err
	}
	inbound, err := s.inbound(ctx, s.cfg.WARP.InnerTag)
	if err != nil {
		return nil, err
	}
	chain, err := clientcfg.WARPChain(s.cfg, inbound, inner, account, s.cfg.NodeTags.WARP)
	if err != nil {
		return nil, fmt.Errorf("service: build the WARP chain: %w", err)
	}
	return append(nodes, chain), nil
}

// chainUser gets the account a chain leg authenticates with.
func (s *Service) chainUser(ctx context.Context, tag, uid string, provision bool) (clientcfg.User, bool, error) {
	if !provision {
		return s.existingUser(ctx, tag, uid)
	}
	account, err := s.prov.EnsureUser(ctx, tag, uid)
	if err != nil {
		return clientcfg.User{}, false, err
	}
	user, err := clientcfg.ParseUser(account.User)
	if err != nil {
		return clientcfg.User{}, false, fmt.Errorf("service: parse user on %s: %w", tag, err)
	}
	return user, true, nil
}

// endpointLabel is the node tag a WireGuard endpoint is served under.
//
// From NodeTags rather than from the interface captions, and the two are not
// the same thing: a caption is what a button reads, while this is a node tag a
// client keys its saved selection by. Renaming it is a new node appearing and
// the old one vanishing, which costs the user their choice.
func (s *Service) endpointLabel(tag string) string {
	switch tag {
	case s.cfg.Tags.AWG:
		return s.cfg.NodeTags.AWG
	case s.cfg.Tags.AWG3:
		return s.cfg.NodeTags.AWG3
	}
	return s.cfg.NodeTags.AWG
}

// udpHost is where a UDP endpoint is reached: the A-only name when there is
// one, since both WireGuard and the VK relay are IPv4-only.
func (s *Service) udpHost() string {
	if s.cfg.Public.IPv4Host != "" {
		return s.cfg.Public.IPv4Host
	}
	return s.cfg.Public.Host
}
