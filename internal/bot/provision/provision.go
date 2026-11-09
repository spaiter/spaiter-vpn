// Package provision gives a user what they need to connect: an account on each
// proxy inbound, a WireGuard peer on each endpoint, a relay password.
//
// Every operation is idempotent and reads the live core rather than the files
// on disk. The files record what was handed out; the core decides what exists.
// Asking the core is what keeps six live users from being re-provisioned when
// this binary replaces the one that first served them.
//
// Nothing here applies configuration. Callers open a reload batch, provision
// everything, and close it, so one button press costs one apply.
package provision

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// API is the part of the core's management interface this package uses.
type API interface {
	Inbound(ctx context.Context, tag string) (json.RawMessage, error)
	Users(ctx context.Context, tag string) ([]json.RawMessage, error)
	AddUser(ctx context.Context, tag string, user any) error
	Endpoint(ctx context.Context, tag string) (json.RawMessage, error)
	PutEndpoint(ctx context.Context, tag string, endpoint any) error
}

// Reloader asks for the written configuration to be applied. Inside a batch
// this only raises a flag, which is the point.
type Reloader interface {
	Request(ctx context.Context) error
}

// Provisioner hands out accounts and peers.
type Provisioner struct {
	api   API
	store *state.Store
	rl    Reloader
	log   *slog.Logger

	// Each endpoint is read, modified and written back whole, so two
	// provisionings against the same one must not interleave: both would
	// compute the same free address and the second write would drop the first
	// one's peer. Per endpoint rather than global, since endpoints are
	// independent and WireGuard key generation is not fast.
	endpointMu sync.Map // tag -> *sync.Mutex
}

// New builds a provisioner.
func New(api API, store *state.Store, rl Reloader, log *slog.Logger) *Provisioner {
	if log == nil {
		log = slog.Default()
	}
	return &Provisioner{api: api, store: store, rl: rl, log: log}
}

func (p *Provisioner) lock(tag string) *sync.Mutex {
	mu, _ := p.endpointMu.LoadOrStore(tag, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// Account is a user's entry on one inbound, together with the inbound it
// belongs to: both are needed to render a link, and fetching the inbound again
// afterwards would race with a config change.
type Account struct {
	// Inbound is the live inbound as the core reports it.
	Inbound json.RawMessage
	// User is the account object, either the one already there or the new one.
	User json.RawMessage
	// Created says whether this call minted it. A caller that provisions a
	// dozen inbounds uses this to decide whether an apply is needed at all.
	Created bool
}

// EnsureUser returns the user's account on an inbound, creating it if absent.
//
// It never applies: a caller provisioning thirteen inbounds would otherwise pay
// thirteen round trips. On a new account it asks the reloader, which inside a
// batch costs nothing.
func (p *Provisioner) EnsureUser(ctx context.Context, tag, uid string) (Account, error) {
	inbound, err := p.api.Inbound(ctx, tag)
	if err != nil {
		return Account{}, fmt.Errorf("provision: inbound %s: %w", tag, err)
	}
	var meta struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(inbound, &meta); err != nil {
		return Account{}, fmt.Errorf("provision: inbound %s is not an object: %w", tag, err)
	}

	existing, err := p.api.Users(ctx, tag)
	if err != nil {
		return Account{}, fmt.Errorf("provision: users of %s: %w", tag, err)
	}
	for _, u := range existing {
		if UserKey(u) == uid {
			return Account{Inbound: inbound, User: u}, nil
		}
	}

	var account map[string]any
	if meta.Type == "mtproto" {
		account, err = mtprotoCredentials(inbound, uid)
	} else {
		account, err = Credentials(meta.Type, uid)
	}
	if err != nil {
		return Account{}, fmt.Errorf("provision: credentials for %s on %s: %w", meta.Type, tag, err)
	}
	if err := p.api.AddUser(ctx, tag, account); err != nil {
		return Account{}, fmt.Errorf("provision: add %s to %s: %w", uid, tag, err)
	}
	encoded, err := json.Marshal(account)
	if err != nil {
		return Account{}, fmt.Errorf("provision: encode the new account: %w", err)
	}

	// The core holds the account but no live inbound is serving it yet.
	if err := p.rl.Request(ctx); err != nil {
		return Account{}, fmt.Errorf("provision: apply after adding %s to %s: %w", uid, tag, err)
	}
	p.log.Info("provisioned a user", "uid", uid, "inbound", tag, "type", meta.Type)
	return Account{Inbound: inbound, User: encoded, Created: true}, nil
}

// UserKey is how a user object is identified across inbound types. Most are
// keyed by name; naive and mieru carry a username instead, and reading the
// wrong field makes every lookup miss and every account be minted twice.
func UserKey(user json.RawMessage) string {
	var u struct {
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(user, &u); err != nil {
		return ""
	}
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}

// Credentials mints the account object for one inbound type.
//
// The shapes are the core's, not this package's: a field named wrong is
// accepted by the API and then ignored by the inbound, which produces a user
// who exists in the config and cannot authenticate.
func Credentials(inboundType, name string) (map[string]any, error) {
	switch inboundType {
	case "vless", "vmess":
		uuid, err := keys.UUID()
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "uuid": uuid}, nil

	case "hysteria2", "trojan":
		password, err := keys.Password(16)
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "password": password}, nil

	case "shadowsocks":
		// Shadowsocks 2022 keys are raw bytes in standard base64, and the
		// length has to match the method's key size.
		password, err := keys.Base64(16)
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "password": password}, nil

	case "tuic":
		uuid, err := keys.UUID()
		if err != nil {
			return nil, err
		}
		password, err := keys.Password(12)
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "uuid": uuid, "password": password}, nil

	case "naive", "mieru":
		// Username-keyed: these two authenticate by username/password pair and
		// have no name field at all.
		password, err := keys.Password(18)
		if err != nil {
			return nil, err
		}
		return map[string]any{"username": name, "password": password}, nil

	case "snell":
		// A per-user key beside the inbound's shared PSK, not a password.
		userkey, err := keys.Password(18)
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "userkey": userkey}, nil

	default:
		// A password is what most inbounds want; an unknown type is more likely
		// a new protocol than a mistake, and failing here would block the whole
		// bundle over one inbound.
		password, err := keys.Password(16)
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "password": password}, nil
	}
}

// mtprotoCredentials mints a user's fake-TLS secret for the inbound's front
// domain, which every secret on one inbound shares: the core matches a
// connection to its user by the secret, and the domain is part of it.
func mtprotoCredentials(inbound json.RawMessage, name string) (map[string]any, error) {
	var options struct {
		Secret string `json:"secret"`
		Users  []struct {
			Secret string `json:"secret"`
		} `json:"users"`
	}
	if err := json.Unmarshal(inbound, &options); err != nil {
		return nil, err
	}
	source := options.Secret
	if len(options.Users) > 0 {
		source = options.Users[0].Secret
	}
	domain, ok := mtprotoFrontDomain(source)
	if !ok {
		return nil, fmt.Errorf("the mtproto inbound has no fake-TLS secret to take the front domain from")
	}
	secret, err := keys.MTProtoFakeTLSSecret(domain)
	if err != nil {
		return nil, err
	}
	return map[string]any{"name": name, "secret": secret}, nil
}

// mtprotoFrontDomain reads the domain out of an ee- secret: "ee", 16 random
// bytes, then the domain, all hex.
func mtprotoFrontDomain(secret string) (string, bool) {
	const randomHexLen = 32
	if !strings.HasPrefix(secret, "ee") || len(secret) <= 2+randomHexLen {
		return "", false
	}
	decoded, err := hex.DecodeString(secret[2+randomHexLen:])
	if err != nil || len(decoded) == 0 {
		return "", false
	}
	return string(decoded), true
}
