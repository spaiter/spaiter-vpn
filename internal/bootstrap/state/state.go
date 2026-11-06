// Package state defines the versioned, secret-free operator intent consumed by
// bootstrap. It deliberately does not describe mutable core or bot state.
package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

const APIVersionV1Alpha1 = "spaiter-vpn/v1alpha1"

// ACMEDefaultProvider is stored explicitly instead of relying on the core's
// empty-value default, which could change underneath an existing desired state.
const ACMEDefaultProvider = "letsencrypt"

// State is the complete, reviewable input to bootstrap. SecretRef values name
// entries in bootstrap's credential store; they are never filesystem paths or
// secret values.
type State struct {
	APIVersion      string           `json:"apiVersion"`
	Deployment      Deployment       `json:"deployment"`
	Bootstrap       Bootstrap        `json:"bootstrap"`
	Bot             Bot              `json:"bot"`
	MigrationPolicy *MigrationPolicy `json:"migrationPolicy,omitempty"`
	// Web configures the web UI bootstrap.manageWeb runs. Omitted when unset,
	// so documents written before it existed keep their digest.
	Web *Web `json:"web,omitempty"`
	// DDNS keeps bot.publicHost (and bot.publicIpv4Host) on this server's
	// public address, for a server whose address changes. Omitted when unset.
	DDNS *DDNS `json:"ddns,omitempty"`
}

// DDNS is the dynamic DNS updater bootstrap runs as its own unit.
type DDNS struct {
	// Provider is cloudflare, duckdns or dyndns2.
	Provider string `json:"provider"`
	// Token is the API token (cloudflare: Zone:DNS:Edit; duckdns: the
	// account token; dyndns2: the password), stored with `bootstrap credential`.
	Token SecretRef `json:"token"`
	// Username and Server are dyndns2's account and update service.
	Username string `json:"username,omitempty"`
	Server   string `json:"server,omitempty"`
	// IPv6 also keeps the AAAA record of bot.publicHost.
	IPv6 bool `json:"ipv6,omitempty"`
}

// Web is where the web UI listens and the address people reach it at.
type Web struct {
	// Listen defaults to loopback; anything else needs PublicURL on HTTPS.
	Listen string `json:"listen,omitempty"`
	// PublicURL is what login links point at, such as an HTTPS reverse proxy
	// in front of Listen. Defaults to http://<Listen>.
	PublicURL string `json:"publicUrl,omitempty"`
}

// DefaultWebListen keeps the web UI off the network until HTTPS is in front.
const DefaultWebListen = "127.0.0.1:10880"

// WebListen and WebURL resolve the web settings with their defaults.
func (s State) WebListen() string {
	if s.Web != nil && s.Web.Listen != "" {
		return s.Web.Listen
	}
	return DefaultWebListen
}

func (s State) WebURL() string {
	if s.Web != nil && s.Web.PublicURL != "" {
		return s.Web.PublicURL
	}
	return "http://" + s.WebListen()
}

// MigrationPolicy is an exact, reviewable authorization for migrations that
// cannot be inferred safely from the desired end state alone. Policies remain
// in desired.json as an audit record; exact from/to matching prevents them
// from authorizing a later, unrelated migration.
type MigrationPolicy struct {
	Subnets           map[profile.Protocol]SubnetMigration `json:"subnets,omitempty"`
	SeedUsers         *SeedUsersMigration                  `json:"seedUsers,omitempty"`
	RotateCredentials *CredentialRotation                  `json:"rotateCredentials,omitempty"`
}

type SubnetMigration struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Strategy string `json:"strategy"`
}

const SubnetStrategyPreserveHost = "preserve-host"

type SeedUsersMigration struct {
	From     []string `json:"from"`
	To       []string `json:"to"`
	Strategy string   `json:"strategy"`
}

const SeedUsersStrategyPreserveExisting = "preserve-existing"

// CredentialRotation reissues every per-user credential of the named users:
// proxy accounts, WireGuard peer keypairs at their existing addresses, the
// WG-over-VK relay password and the bot's subscription token. Deployment-wide
// secrets are not per-user and are left alone.
//
// Rotation is an event rather than an end state, so ID makes it one-shot: an
// entry identical to the previous desired state's is a retained audit record,
// and only a new ID reissues anything again.
type CredentialRotation struct {
	ID       string   `json:"id"`
	Users    []string `json:"users"`
	Strategy string   `json:"strategy"`
}

const CredentialRotationStrategyReissue = "reissue"

// AuthorizedSubnetMigrations returns the exact subnet moves authorized by the
// proposed state. The previous state is part of the check: a policy is not a
// standing permission and every new policy entry must accompany one real move.
// An entry identical to previous.MigrationPolicy whose subnet is already at To
// is accepted as a retained audit record without triggering a second move.
func (s State) AuthorizedSubnetMigrations(previous State) (map[profile.Protocol]SubnetMigration, error) {
	changed := map[profile.Protocol]SubnetMigration{}
	for protocol, before := range previous.Deployment.Subnets {
		after := s.Deployment.Subnets[protocol]
		if before == after {
			continue
		}
		if s.MigrationPolicy == nil {
			return nil, fmt.Errorf("subnet %q changes from %s to %s without migrationPolicy", protocol, before, after)
		}
		policy, ok := s.MigrationPolicy.Subnets[protocol]
		if !ok || policy.From != before || policy.To != after || policy.Strategy != SubnetStrategyPreserveHost {
			return nil, fmt.Errorf("subnet %q change %s -> %s has no exact preserve-host authorization", protocol, before, after)
		}
		changed[protocol] = policy
	}
	if s.MigrationPolicy != nil {
		for protocol, policy := range s.MigrationPolicy.Subnets {
			if _, ok := changed[protocol]; ok {
				continue
			}
			if previous.MigrationPolicy != nil {
				if prev, hadPrev := previous.MigrationPolicy.Subnets[protocol]; hadPrev && prev == policy && previous.Deployment.Subnets[protocol] == policy.To && s.Deployment.Subnets[protocol] == policy.To {
					continue
				}
			}
			return nil, fmt.Errorf("migrationPolicy.subnets[%q] does not accompany an actual subnet change", protocol)
		}
	}
	return changed, nil
}

// AuthorizedSeedUserMigration returns the exact seed-user transition authorized
// by the proposed state. An entry identical to previous.MigrationPolicy.SeedUsers
// when bootstrap.seedUsers is already at To is accepted as a retained audit
// record and returns (nil, nil).
func (s State) AuthorizedSeedUserMigration(previous State) (*SeedUsersMigration, error) {
	before := previous.Bootstrap.SeedUsers
	after := s.Bootstrap.SeedUsers
	if slices.Equal(before, after) {
		if s.MigrationPolicy != nil && s.MigrationPolicy.SeedUsers != nil {
			policy := s.MigrationPolicy.SeedUsers
			if previous.MigrationPolicy != nil && previous.MigrationPolicy.SeedUsers != nil &&
				seedUsersMigrationEqual(*previous.MigrationPolicy.SeedUsers, *policy) &&
				slices.Equal(before, policy.To) {
				return nil, nil
			}
			return nil, fmt.Errorf("migrationPolicy.seedUsers does not accompany an actual seedUsers change")
		}
		return nil, nil
	}
	if s.MigrationPolicy == nil || s.MigrationPolicy.SeedUsers == nil {
		return nil, fmt.Errorf("bootstrap.seedUsers changes from %v to %v without migrationPolicy.seedUsers", before, after)
	}
	policy := s.MigrationPolicy.SeedUsers
	if !slices.Equal(policy.From, before) || !slices.Equal(policy.To, after) || policy.Strategy != SeedUsersStrategyPreserveExisting {
		return nil, fmt.Errorf("bootstrap.seedUsers change %v -> %v has no exact preserve-existing authorization", before, after)
	}
	return &SeedUsersMigration{
		From:     append([]string(nil), policy.From...),
		To:       append([]string(nil), policy.To...),
		Strategy: policy.Strategy,
	}, nil
}

// AuthorizedCredentialRotation returns the rotation the proposed state asks for,
// or nil when there is none or the entry is the previous state's retained audit
// record. Reusing an ID for a different rotation is refused: the ID is what
// tells a request apart from its record.
func (s State) AuthorizedCredentialRotation(previous State) (*CredentialRotation, error) {
	if s.MigrationPolicy == nil || s.MigrationPolicy.RotateCredentials == nil {
		return nil, nil
	}
	rotation := s.MigrationPolicy.RotateCredentials
	if previous.MigrationPolicy != nil && previous.MigrationPolicy.RotateCredentials != nil {
		prev := previous.MigrationPolicy.RotateCredentials
		if credentialRotationEqual(*prev, *rotation) {
			return nil, nil
		}
		if prev.ID == rotation.ID {
			return nil, fmt.Errorf("migrationPolicy.rotateCredentials.id %q was already used for a different rotation; choose a new id", rotation.ID)
		}
	}
	if rotation.Strategy != CredentialRotationStrategyReissue {
		return nil, fmt.Errorf("migrationPolicy.rotateCredentials.strategy %q is unsupported (supported: %q)", rotation.Strategy, CredentialRotationStrategyReissue)
	}
	return &CredentialRotation{
		ID:       rotation.ID,
		Users:    append([]string(nil), rotation.Users...),
		Strategy: rotation.Strategy,
	}, nil
}

func credentialRotationEqual(a, b CredentialRotation) bool {
	return a.ID == b.ID && a.Strategy == b.Strategy && slices.Equal(a.Users, b.Users)
}

func seedUsersMigrationEqual(a, b SeedUsersMigration) bool {
	return a.Strategy == b.Strategy && slices.Equal(a.From, b.From) && slices.Equal(a.To, b.To)
}

type Deployment struct {
	Image              string                      `json:"image"`
	Tier               profile.Tier                `json:"tier"`
	Protocols          Protocols                   `json:"protocols"`
	Ports              map[profile.Protocol]uint16 `json:"ports"`
	Subnets            map[profile.Protocol]string `json:"subnets"`
	MTU                map[profile.Protocol]uint32 `json:"mtu"`
	XDPInterfaces      []string                    `json:"xdpInterfaces"`
	LogLevel           string                      `json:"logLevel"`
	Domain             string                      `json:"domain"`
	Certificates       *Certificates               `json:"certificates,omitempty"`
	RealityHandshake   Handshake                   `json:"realityHandshake"`
	ShadowTLSHandshake Handshake                   `json:"shadowTlsHandshake"`
	MTProtoFrontDomain string                      `json:"mtprotoFrontDomain"`
	// RetireSharedMTProto drops the legacy MTProto secret everyone shared,
	// once users have their own links. Omitted when false, so documents written
	// before it existed keep their digest.
	RetireSharedMTProto bool `json:"retireSharedMtproto,omitempty"`
	// MTProtoPerUser gives each user their own MTProto secret, attributed and
	// limited per user. Needs a core image built with MTProto users, so it is
	// off until the default image has them.
	MTProtoPerUser bool `json:"mtprotoPerUser,omitempty"`
}

type Protocols struct {
	Disabled []profile.Protocol `json:"disabled"`
}

type Handshake struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// Certificates is a tagged union. Exactly the branch named by Source must be
// present, and all other branches must be absent.
type Certificates struct {
	Source   profile.CertSource `json:"source"`
	Files    *CertificateFiles  `json:"files,omitempty"`
	ACMEHTTP *ACMEHTTP          `json:"acmeHttp,omitempty"`
	ACMEDNS  *ACMEDNS           `json:"acmeDns,omitempty"`
}

type CertificateFiles struct {
	CertificatePath string `json:"certificatePath"`
	KeyPath         string `json:"keyPath"`
}

type ACMEHTTP struct {
	Email           string `json:"email"`
	Directory       string `json:"directory"`
	DataDirectory   string `json:"dataDirectory"`
	AlternativePort uint16 `json:"alternativePort"`
}

type ACMEDNS struct {
	Email         string          `json:"email"`
	Directory     string          `json:"directory"`
	DataDirectory string          `json:"dataDirectory"`
	Provider      string          `json:"provider"`
	Cloudflare    *CloudflareDNS  `json:"cloudflare,omitempty"`
	Account       *ACMEDNSAccount `json:"account,omitempty"`
}

type CloudflareDNS struct {
	APIToken SecretRef `json:"apiToken"`
}

type ACMEDNSAccount struct {
	Username  string    `json:"username"`
	Password  SecretRef `json:"password"`
	Subdomain string    `json:"subdomain"`
	ServerURL string    `json:"serverUrl"`
}

// SecretRef is a logical name in the fixed bootstrap credential directory.
// Slashes and dots are rejected so it cannot become an arbitrary path.
type SecretRef string

type Bootstrap struct {
	SeedUsers       []string `json:"seedUsers"`
	InstallDocker   bool     `json:"installDocker"`
	ManageFirewall  bool     `json:"manageFirewall"`
	ManageLogrotate bool     `json:"manageLogrotate"`
	// ManageControl installs and runs the local control daemon and gives the
	// bot its socket. Omitted when false, so documents written before it
	// existed keep their digest.
	ManageControl bool `json:"manageControl,omitempty"`
	// ManageWeb installs and runs the web UI as its own account; it needs
	// ManageControl, whose daemon it talks to.
	ManageWeb bool `json:"manageWeb,omitempty"`
}

type Bot struct {
	Enabled    bool    `json:"enabled"`
	AdminIDs   []int64 `json:"adminIds"`
	PublicHost string  `json:"publicHost"`
	// DynamicIP records that the server's public address changes, so
	// publicHost must be a domain kept current by dynamic DNS: a client
	// config holding the address stops working when it changes. Omitted when
	// false, so older documents keep their digest.
	DynamicIP              bool   `json:"dynamicIp,omitempty"`
	SubscriptionHost       string `json:"subscriptionHost"`
	DirectSubscriptionHost string `json:"directSubscriptionHost"`
	SubscriptionPort       uint16 `json:"subscriptionPort"`
	// WDTTConfigDirectory is the host directory mounted into vpn-bot at
	// /wdtt-cfg and into the externally managed wdtt-relay at its config
	// directory. Its passwords.json is runtime state and joins an authorized
	// wg-wdtt-in subnet migration transaction.
	WDTTConfigDirectory string    `json:"wdttConfigDirectory"`
	TelegramToken       SecretRef `json:"telegramToken,omitempty"`
	// DedicatedUser runs the bot as the unprivileged system user
	// spaiter-vpn-bot instead of root, without the core's configuration
	// mounted: it sees only the management endpoint and secret it needs. New
	// documents set it; omitted when false, so older ones keep their digest
	// and their root bot until the operator switches.
	DedicatedUser bool `json:"dedicatedUser,omitempty"`
	// TelegramAPIURL points the bot at another Bot API server, such as a
	// self-hosted telegram-bot-api. Empty uses Telegram's.
	TelegramAPIURL string `json:"telegramApiUrl,omitempty"`
	// PublicIPv4Host is an A-only name for the UDP methods, for a publicHost
	// that also resolves to IPv6: VK's TURN has no IPv6, and a client that
	// dials the AAAA first reaches nothing. Empty uses publicHost.
	PublicIPv4Host string `json:"publicIpv4Host,omitempty"`
	// CDNHost is the CDN edge, with TLS on 443, the CDN-fronted VLESS
	// inbound is reached through. Empty offers it at publicHost directly.
	CDNHost string `json:"cdnHost,omitempty"`
}

// Default returns a fully populated Tier-A state. Defaults belong here, at
// document creation time; Decode never fills missing values behind the
// operator's back.
func Default(seedUsers []string) State {
	spec := profile.Defaults(seedUsers)
	subnets := make(map[profile.Protocol]string, len(spec.Subnets))
	for protocol, prefix := range spec.Subnets {
		subnets[protocol] = prefix.String()
	}

	return State{
		APIVersion: APIVersionV1Alpha1,
		Deployment: Deployment{
			Image:         singbox.DefaultImage,
			Tier:          profile.TierA,
			Protocols:     Protocols{Disabled: []profile.Protocol{}},
			Ports:         cloneMap(spec.Ports),
			Subnets:       subnets,
			MTU:           cloneMap(spec.MTU),
			XDPInterfaces: []string{"auto"},
			LogLevel:      spec.LogLevel,
			Domain:        "",
			RealityHandshake: Handshake{
				Host: spec.RealityHandshakeServer,
				Port: spec.RealityHandshakePort,
			},
			ShadowTLSHandshake: Handshake{
				Host: spec.ShadowTLSHandshakeServer,
				Port: spec.ShadowTLSHandshakePort,
			},
			MTProtoFrontDomain: spec.MTProtoFrontDomain,
		},
		Bootstrap: Bootstrap{
			SeedUsers:       append([]string(nil), seedUsers...),
			ManageFirewall:  true,
			ManageLogrotate: true,
		},
		Bot: Bot{
			AdminIDs:         []int64{},
			SubscriptionPort: deploy.DefaultBotSubPort,
			DedicatedUser:    true,
		},
	}
}

func cloneMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// Decode reads exactly one strict desired-state document. Version dispatch is
// kept separate even while only v1alpha1 exists, so adding a migration later
// does not weaken strict decoding of the current schema.
func Decode(r io.Reader) (State, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return State{}, fmt.Errorf("read desired state: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (State, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return State{}, err
	}

	var envelope struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return State{}, fmt.Errorf("decode desired state: %w", err)
	}

	switch envelope.APIVersion {
	case APIVersionV1Alpha1:
		if err := requireFields(data, reflect.TypeOf(State{}), "desired state"); err != nil {
			return State{}, err
		}
		var result State
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&result); err != nil {
			return State{}, fmt.Errorf("decode desired state %s: %w", envelope.APIVersion, err)
		}
		if err := ensureEOF(decoder); err != nil {
			return State{}, err
		}
		if err := result.Validate(); err != nil {
			return State{}, err
		}
		return result, nil
	case "":
		return State{}, fmt.Errorf("desired state has no apiVersion")
	default:
		return State{}, fmt.Errorf("unsupported desired-state apiVersion %q (supported: %q)", envelope.APIVersion, APIVersionV1Alpha1)
	}
}

// rejectDuplicateKeys prevents a document from showing one value to a human
// reviewer and applying the last duplicate seen by encoding/json.
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder, "desired state"); err != nil {
		return err
	}
	return ensureEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}

	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode %s object key: %w", path, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("decode %s: object key is not a string", path)
			}
			if seen[key] {
				return fmt.Errorf("%s contains duplicate field %q", path, key)
			}
			seen[key] = true
			if err := scanJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("decode closing %s object: %w", path, err)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("decode closing %s array: %w", path, err)
		}
	default:
		return fmt.Errorf("decode %s: unexpected JSON delimiter %q", path, delim)
	}
	return nil
}

// requireFields makes zero values explicit. Without it, a missing false, zero
// or empty string is indistinguishable from an operator who deliberately
// stored that value, defeating the promise that defaults are applied only
// when a document is created.
func requireFields(data []byte, typ reflect.Type, path string) error {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return requireRawFields(raw, typ, path)
}

func requireRawFields(raw json.RawMessage, typ reflect.Type, path string) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s must be an object, not null", path)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return fmt.Errorf("decode %s object: %w", path, err)
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		name, options, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		value, present := object[name]
		if !present {
			if strings.Contains(options, "omitempty") {
				continue
			}
			return fmt.Errorf("%s is missing required field %q", path, name)
		}

		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("%s.%s must not be null", path, name)
			}
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			if err := requireRawFields(value, field.Type, path+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing desired-state data: %w", err)
	}
	return fmt.Errorf("desired state contains more than one JSON value")
}

func Load(path string) (State, error) {
	file, err := os.Open(path)
	if err != nil {
		return State{}, fmt.Errorf("open desired state %s: %w", path, err)
	}
	defer file.Close()
	return Decode(file)
}

// Validate rejects anything that is not a logical credential name, so a
// reference can never become a path.
func (r SecretRef) Validate(field string) error {
	value := string(r)
	if value == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(value) > 64 {
		return fmt.Errorf("%s is longer than 64 characters", field)
	}
	for i, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && i > 0) {
			continue
		}
		return fmt.Errorf("%s %q is not a logical credential name (use lowercase letters, digits and internal hyphens)", field, value)
	}
	if strings.HasSuffix(value, "-") {
		return fmt.Errorf("%s %q ends with a hyphen", field, value)
	}
	return nil
}
