// Package service turns a user id into something they can import.
//
// It sits between the generators, which are pure, and the interface, which is
// text and buttons. Everything that has to talk to both the live core and the
// files on disk lives here, so neither the Telegram layer nor the background
// loops has to know how a bundle is put together.
//
// The split that matters is provisioning. An interactive button press creates
// whatever is missing; a background refresh and an HTTP request must never
// create anything -- they rebuild from what the user already has. The same code
// serves both, because two implementations of "what this user's configuration
// is" would drift and the drift would only show up as a client that stopped
// connecting.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/provision"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// API is what the service needs from the core's management interface.
type API interface {
	provision.API
	Inbounds(ctx context.Context) ([]manage.InboundRef, error)
	DeleteUser(ctx context.Context, tag, name string) error
	ResetUserStats(ctx context.Context, name string) error
	Endpoints(ctx context.Context) ([]json.RawMessage, error)
	UserStats(ctx context.Context) ([]manage.UserStat, error)
}

// Batcher collapses the applies of one provisioning run into one.
type Batcher interface {
	Begin(ctx context.Context) (context.Context, func())
	Request(ctx context.Context) error
}

// Service assembles a user's configuration.
type Service struct {
	cfg       bot.Config
	api       API
	prov      *provision.Provisioner
	store     *state.Store
	batch     Batcher
	registrar provision.Registrar
	log       *slog.Logger
}

// New builds a service.
func New(cfg bot.Config, api API, prov *provision.Provisioner, store *state.Store,
	batch Batcher, registrar provision.Registrar, log *slog.Logger,
) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg: cfg, api: api, prov: prov, store: store,
		batch: batch, registrar: registrar, log: log,
	}
}

// Config exposes the configuration the interface renders itself from.
func (s *Service) Config() bot.Config { return s.cfg }

// UserInbounds lists the inbounds that have per-user accounts, which is what
// the protocol menu is built from.
//
// Read from the live core rather than from a list in the configuration: a
// protocol added to the deployment has to appear here without anyone editing
// the bot, and one removed must stop being offered.
func (s *Service) UserInbounds(ctx context.Context) ([]manage.InboundRef, error) {
	all, err := s.api.Inbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("service: list inbounds: %w", err)
	}
	userTypes := bot.UserTypes()
	out := make([]manage.InboundRef, 0, len(all))
	for _, inbound := range all {
		if !userTypes[inbound.Type] {
			continue
		}
		// MTProto has users only on a core that matches secrets to them. On
		// an older one it is a single shared secret, which nobody can be
		// provisioned on: offering it would mint accounts that core rejects.
		// Ask the core rather than count accounts: its users resource answers
		// 400 "does not support users" on such a core, and a list -- empty
		// included -- on one that has them. An empty list is the normal start
		// of a deployment that kept only its shared secret; the first user is
		// provisioned on request, so hiding the method until someone already
		// has an account would mean nobody ever could.
		if inbound.Type == "mtproto" {
			if _, err := s.api.Users(ctx, inbound.Tag); err != nil {
				if errors.Is(err, manage.ErrBadRequest) {
					continue
				}
				return nil, fmt.Errorf("service: users of %s: %w", inbound.Tag, err)
			}
		}
		out = append(out, inbound)
	}
	return out, nil
}

// OfferedEndpoints lists the WireGuard endpoints a user can be handed directly.
//
// The MASQUE and VK endpoints are excluded: they are internal plain-WireGuard
// targets that something else forwards into, and handing one out as an Amnezia
// profile would give the user a tunnel to a port nothing listens on from
// outside.
func (s *Service) OfferedEndpoints(ctx context.Context) ([]clientcfg.Endpoint, error) {
	raw, err := s.api.Endpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("service: list endpoints: %w", err)
	}
	internal := []string{s.cfg.Tags.MASQUEWG, s.cfg.WDTT.Tag}

	out := make([]clientcfg.Endpoint, 0, len(raw))
	for _, item := range raw {
		var endpoint clientcfg.Endpoint
		if err := json.Unmarshal(item, &endpoint); err != nil {
			return nil, fmt.Errorf("service: parse endpoint: %w", err)
		}
		if endpoint.Type != "awg" || slices.Contains(internal, endpoint.Tag) {
			continue
		}
		out = append(out, endpoint)
	}
	return out, nil
}

// inbound fetches one inbound's detail.
//
// The list is a summary of tags and types; the detail carries the port, the TLS
// settings and the transport, without which no usable node can be built.
func (s *Service) inbound(ctx context.Context, tag string) (clientcfg.Inbound, error) {
	raw, err := s.api.Inbound(ctx, tag)
	if err != nil {
		return clientcfg.Inbound{}, fmt.Errorf("service: inbound %s: %w", tag, err)
	}
	inbound, err := clientcfg.ParseInbound(raw)
	if err != nil {
		return clientcfg.Inbound{}, fmt.Errorf("service: parse inbound %s: %w", tag, err)
	}
	return inbound, nil
}

// endpoint fetches one endpoint.
func (s *Service) endpoint(ctx context.Context, tag string) (clientcfg.Endpoint, error) {
	raw, err := s.api.Endpoint(ctx, tag)
	if err != nil {
		return clientcfg.Endpoint{}, fmt.Errorf("service: endpoint %s: %w", tag, err)
	}
	var endpoint clientcfg.Endpoint
	if err := json.Unmarshal(raw, &endpoint); err != nil {
		return clientcfg.Endpoint{}, fmt.Errorf("service: parse endpoint %s: %w", tag, err)
	}
	return endpoint, nil
}

// existingUser finds a user's account on an inbound without creating one.
//
// found is false when they have none, which is a normal answer rather than an
// error: that is exactly what the refresh loop sees for a method the user has
// never asked for.
func (s *Service) existingUser(ctx context.Context, tag, uid string) (clientcfg.User, bool, error) {
	accounts, err := s.api.Users(ctx, tag)
	if err != nil {
		return clientcfg.User{}, false, fmt.Errorf("service: users of %s: %w", tag, err)
	}
	for _, raw := range accounts {
		if provision.UserKey(raw) != uid {
			continue
		}
		user, err := clientcfg.ParseUser(raw)
		if err != nil {
			return clientcfg.User{}, false, fmt.Errorf("service: parse user on %s: %w", tag, err)
		}
		return user, true, nil
	}
	return clientcfg.User{}, false, nil
}

// Label is the name a method is shown under.
func (s *Service) Label(inbound clientcfg.Inbound) string {
	return clientcfg.NodeLabel(s.cfg, inbound)
}

// Link hands out a share URI, creating the account if the user has none.
func (s *Service) Link(ctx context.Context, tag, uid string) (string, error) {
	ctx, done := s.batch.Begin(ctx)
	defer done()

	account, err := s.prov.EnsureUser(ctx, tag, uid)
	if err != nil {
		return "", err
	}
	inbound, err := clientcfg.ParseInbound(account.Inbound)
	if err != nil {
		return "", fmt.Errorf("service: parse inbound %s: %w", tag, err)
	}
	user, err := clientcfg.ParseUser(account.User)
	if err != nil {
		return "", fmt.Errorf("service: parse user on %s: %w", tag, err)
	}

	link, err := clientcfg.Link(s.cfg, inbound, user)
	if err != nil {
		return "", err
	}
	if link == "" {
		return "", fmt.Errorf("service: %s has no share link; it is delivered as a config", tag)
	}
	return link, nil
}

// JSONConfig hands out a whole client config, for the protocols that have no
// usable share URI.
func (s *Service) JSONConfig(ctx context.Context, tag, uid string) ([]byte, error) {
	ctx, done := s.batch.Begin(ctx)
	defer done()

	account, err := s.prov.EnsureUser(ctx, tag, uid)
	if err != nil {
		return nil, err
	}
	inbound, err := clientcfg.ParseInbound(account.Inbound)
	if err != nil {
		return nil, fmt.Errorf("service: parse inbound %s: %w", tag, err)
	}
	user, err := clientcfg.ParseUser(account.User)
	if err != nil {
		return nil, fmt.Errorf("service: parse user on %s: %w", tag, err)
	}

	in := clientcfg.JSONConfigInput{Inbound: inbound, User: user}
	// ShadowTLS is a front for a shadowsocks inbound, and the client needs both
	// halves: the credential it authenticates with and the one behind it.
	if inbound.Type == "shadowtls" && inbound.Detour != "" {
		backend, err := s.inbound(ctx, inbound.Detour)
		if err != nil {
			return nil, err
		}
		in.Backend = &backend
	}
	return clientcfg.JSONConfig(s.cfg, in)
}

// AWGConf hands out an AmneziaWG profile, provisioning the peer if needed.
func (s *Service) AWGConf(ctx context.Context, tag, uid string) (string, error) {
	ctx, done := s.batch.Begin(ctx)
	defer done()

	peer, err := s.prov.EnsurePeer(ctx, tag, uid)
	if err != nil {
		return "", err
	}
	endpoint, err := s.endpoint(ctx, tag)
	if err != nil {
		return "", err
	}
	address := fmt.Sprintf("%s:%d", s.cfg.Public.Host, peer.ListenPort)
	return clientcfg.WireGuardConf(endpoint, state.Peer{
		Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: peer.Address,
	}, address, s.cfg.Public.DNS)
}

// WARPChainConfig hands out the whitelist-escape path: in through Cloudflare,
// out through this server, so the user keeps our egress address.
func (s *Service) WARPChainConfig(ctx context.Context, uid string) ([]byte, error) {
	ctx, done := s.batch.Begin(ctx)
	defer done()

	account, err := s.prov.EnsureWARP(ctx, uid, s.registrar)
	if err != nil {
		return nil, err
	}
	inner, err := s.prov.EnsureUser(ctx, s.cfg.WARP.InnerTag, uid)
	if err != nil {
		return nil, err
	}
	inbound, err := clientcfg.ParseInbound(inner.Inbound)
	if err != nil {
		return nil, fmt.Errorf("service: parse %s: %w", s.cfg.WARP.InnerTag, err)
	}
	user, err := clientcfg.ParseUser(inner.User)
	if err != nil {
		return nil, fmt.Errorf("service: parse user on %s: %w", s.cfg.WARP.InnerTag, err)
	}

	chain, err := clientcfg.WARPChain(s.cfg, inbound, user, account,
		clientcfg.NodeLabel(s.cfg, inbound))
	if err != nil {
		return nil, err
	}
	return singleMethodConfig(chain.Legs)
}

// WDTTConfig hands out the WG-over-VK path.
func (s *Service) WDTTConfig(ctx context.Context, uid string) ([]byte, error) {
	ctx, done := s.batch.Begin(ctx)
	defer done()

	wdtt, err := s.prov.EnsureWDTT(ctx, s.cfg.WDTT.Tag, uid, s.relayPasswordsPath())
	if err != nil {
		return nil, err
	}
	hashes, err := s.store.LiveVKHashes(s.cfg.WDTT.Hashes)
	if err != nil {
		return nil, err
	}
	node := clientcfg.WDTTNode(s.cfg, wdtt.Password, hashes)
	node["tag"] = "proxy"
	return singleMethodConfig([]clientcfg.Node{node})
}

func (s *Service) relayPasswordsPath() string {
	return s.cfg.Paths.WDTTConfigDir + "/passwords.json"
}

// Stats is a user's traffic as the core counted it.
//
// found is false when they have never connected, which is not the same as zero
// and is worth saying differently: zero bytes on a config that was imported is
// a sign something is wrong, while no record at all just means it was not used.
func (s *Service) Stats(ctx context.Context, uid string) (manage.UserStat, bool, error) {
	rows, err := s.api.UserStats(ctx)
	if err != nil {
		return manage.UserStat{}, false, fmt.Errorf("service: user stats: %w", err)
	}
	for _, row := range rows {
		if row.User == uid {
			return row, true, nil
		}
	}
	return manage.UserStat{}, false, nil
}

// AllStats is every user's traffic, for the admin view.
func (s *Service) AllStats(ctx context.Context) ([]manage.UserStat, error) {
	rows, err := s.api.UserStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("service: user stats: %w", err)
	}
	return rows, nil
}

// singleMethodConfig wraps one method's outbounds into the config a client
// imports as a single node.
//
// The local mixed inbound and the route are what make it work standalone: the
// client needs somewhere to send traffic and a default for where it goes. A
// bare outbound list would import and route nothing.
func singleMethodConfig(outbounds []clientcfg.Node) ([]byte, error) {
	list := make([]any, 0, len(outbounds))
	for _, node := range outbounds {
		list = append(list, node)
	}
	config := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "listen": "127.0.0.1", "listen_port": 2080,
		}},
		"outbounds": list,
		"route":     map[string]any{"final": "proxy"},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("service: render config: %w", err)
	}
	return data, nil
}

// DeleteUser removes an account from an inbound.
//
// Irreversible in the way that matters: the credential was generated once and
// only the client holds it, so re-adding the same name produces a different
// account and the old configuration stays dead.
func (s *Service) DeleteUser(ctx context.Context, tag, name string) error {
	ctx, done := s.batch.Begin(ctx)
	defer done()

	if err := s.api.DeleteUser(ctx, tag, name); err != nil {
		return fmt.Errorf("service: delete %s from %s: %w", name, tag, err)
	}
	// The account is out of the config but the running inbound still holds it,
	// so without this the credential keeps working.
	return s.batch.Request(ctx)
}

// ResetStats clears a user's traffic counters.
func (s *Service) ResetStats(ctx context.Context, name string) error {
	if err := s.api.ResetUserStats(ctx, name); err != nil {
		return fmt.Errorf("service: reset the counters of %s: %w", name, err)
	}
	return nil
}

// Accounts maps each account name to the inbounds it exists on.
//
// This is the answer to "who has access", and it is not the same as the user
// registry: the registry records everyone who ever messaged the bot, including
// people who were refused. Nor is it the whitelist, which says who may ask for
// a configuration rather than who holds one -- a user revoked from the
// whitelist keeps working until their accounts are deleted, and an admin
// looking at this list needs to see them.
func (s *Service) Accounts(ctx context.Context) (map[string][]string, error) {
	inbounds, err := s.UserInbounds(ctx)
	if err != nil {
		return nil, err
	}

	accounts := map[string][]string{}
	for _, ref := range inbounds {
		users, err := s.api.Users(ctx, ref.Tag)
		if err != nil {
			return nil, fmt.Errorf("service: users of %s: %w", ref.Tag, err)
		}
		for _, raw := range users {
			name := provision.UserKey(raw)
			if name == "" {
				continue
			}
			accounts[name] = append(accounts[name], ref.Tag)
		}
	}
	for name := range accounts {
		slices.Sort(accounts[name])
		accounts[name] = slices.Compact(accounts[name])
	}
	return accounts, nil
}
