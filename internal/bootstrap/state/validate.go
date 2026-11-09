package state

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func (s State) Validate() error {
	if s.APIVersion != APIVersionV1Alpha1 {
		return fmt.Errorf("unsupported desired-state apiVersion %q", s.APIVersion)
	}
	if err := validateImage(s.Deployment.Image); err != nil {
		return err
	}
	if err := validateUniqueProtocols(s.Deployment.Protocols.Disabled); err != nil {
		return err
	}
	if s.Deployment.Protocols.Disabled == nil {
		return fmt.Errorf("deployment.protocols.disabled must be an array, not null")
	}
	if err := validateXDPInterfaces(s.Deployment.XDPInterfaces); err != nil {
		return err
	}
	if s.Deployment.XDPInterfaces == nil {
		return fmt.Errorf("deployment.xdpInterfaces must be an array, not null (use [] to disable XDP)")
	}
	if s.Deployment.LogLevel == "" {
		return fmt.Errorf("deployment.logLevel is empty")
	}
	if err := validateHandshake("deployment.realityHandshake", s.Deployment.RealityHandshake); err != nil {
		return err
	}
	if err := validateHandshake("deployment.shadowTlsHandshake", s.Deployment.ShadowTLSHandshake); err != nil {
		return err
	}
	if err := validateCompleteMaps(s.Deployment); err != nil {
		return err
	}
	if err := validateBot(s.Bot); err != nil {
		return err
	}
	if err := validateDDNS(s); err != nil {
		return err
	}
	if err := validateWeb(s); err != nil {
		return err
	}
	if err := validateMigrationPolicy(s); err != nil {
		return err
	}

	spec, err := s.profileSpecForValidation()
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("deployment profile: %w", err)
	}
	return nil
}

// validateDDNS checks the updater has something to keep and a way to keep it.
// It never touches the network: whether the token works is the unit's first
// round, which apply waits for.
func validateDDNS(s State) error {
	d := s.DDNS
	if d == nil {
		return nil
	}
	if s.Bot.PublicHost == "" {
		return fmt.Errorf("ddns needs bot.publicHost: the name it keeps on this server")
	}
	if _, err := netip.ParseAddr(s.Bot.PublicHost); err == nil {
		return fmt.Errorf("ddns keeps a name, but bot.publicHost %q is an address", s.Bot.PublicHost)
	}
	if err := d.Token.Validate("ddns.token"); err != nil {
		return err
	}
	switch d.Provider {
	case "cloudflare":
	case "duckdns":
		if !strings.HasSuffix(s.Bot.PublicHost, ".duckdns.org") {
			return fmt.Errorf("ddns.provider duckdns keeps *.duckdns.org names, not %q", s.Bot.PublicHost)
		}
	case "dyndns2":
		if d.Username == "" || !strings.HasPrefix(d.Server, "https://") {
			return fmt.Errorf("ddns.provider dyndns2 needs ddns.username and an https ddns.server")
		}
		if d.IPv6 {
			return fmt.Errorf("ddns.ipv6: dyndns2 keeps IPv4 records only")
		}
	default:
		return fmt.Errorf("ddns.provider %q: known are cloudflare, duckdns and dyndns2", d.Provider)
	}
	if d.Provider != "dyndns2" && (d.Username != "" || d.Server != "") {
		return fmt.Errorf("ddns.username and ddns.server are dyndns2's; %s does not use them", d.Provider)
	}
	return nil
}

func validateWeb(s State) error {
	if s.Web != nil && !s.Bootstrap.ManageWeb {
		return fmt.Errorf("web is set while bootstrap.manageWeb is false")
	}
	if !s.Bootstrap.ManageWeb {
		return nil
	}
	if !s.Bootstrap.ManageControl {
		return fmt.Errorf("bootstrap.manageWeb needs bootstrap.manageControl: the web UI is a client of the control daemon")
	}
	host, port, err := net.SplitHostPort(s.WebListen())
	if err != nil || port == "" {
		return fmt.Errorf("web.listen %q is not host:port", s.WebListen())
	}
	loopback := false
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if s.Web != nil && s.Web.PublicURL != "" {
		parsed, err := url.Parse(s.Web.PublicURL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" {
			return fmt.Errorf("web.publicUrl %q must be an http(s) URL with a host", s.Web.PublicURL)
		}
	}
	if !loopback && !strings.HasPrefix(s.WebURL(), "https://") {
		return fmt.Errorf("web.listen %q is reachable beyond this host, so web.publicUrl must be an https:// address in front of it", s.WebListen())
	}
	return nil
}

func validateMigrationPolicy(s State) error {
	policy := s.MigrationPolicy
	if policy == nil {
		return nil
	}
	if policy.Subnets != nil && len(policy.Subnets) == 0 {
		return fmt.Errorf("migrationPolicy.subnets must be a non-empty object")
	}
	if len(policy.Subnets) == 0 && policy.SeedUsers == nil && policy.RotateCredentials == nil {
		return fmt.Errorf("migrationPolicy must specify subnets, seedUsers or rotateCredentials")
	}
	wireguard := map[profile.Protocol]bool{
		profile.AWG2: true, profile.AWG3: true, profile.WGMasque: true, profile.WGWDTT: true,
	}
	for protocol, migration := range policy.Subnets {
		if !wireguard[protocol] {
			return fmt.Errorf("migrationPolicy.subnets contains non-WireGuard protocol %q", protocol)
		}
		if migration.Strategy != SubnetStrategyPreserveHost {
			return fmt.Errorf("migrationPolicy.subnets[%q].strategy %q is unsupported (supported: %q)", protocol, migration.Strategy, SubnetStrategyPreserveHost)
		}
		from, err := parseCanonicalIPv4Prefix("migrationPolicy.subnets[\""+string(protocol)+"\"].from", migration.From)
		if err != nil {
			return err
		}
		to, err := parseCanonicalIPv4Prefix("migrationPolicy.subnets[\""+string(protocol)+"\"].to", migration.To)
		if err != nil {
			return err
		}
		if from == to {
			return fmt.Errorf("migrationPolicy.subnets[%q] has identical from and to prefixes", protocol)
		}
		if desired := s.Deployment.Subnets[protocol]; desired != migration.To {
			return fmt.Errorf("migrationPolicy.subnets[%q].to %q does not equal deployment.subnets[%q] %q", protocol, migration.To, protocol, desired)
		}
	}
	if policy.SeedUsers != nil {
		if err := validateSeedUsersMigration(*policy.SeedUsers, s.Bootstrap.SeedUsers); err != nil {
			return err
		}
	}
	if policy.RotateCredentials != nil {
		if err := validateCredentialRotation(*policy.RotateCredentials); err != nil {
			return err
		}
	}
	return nil
}

func validateCredentialRotation(rotation CredentialRotation) error {
	if !validRotationID(rotation.ID) {
		return fmt.Errorf("migrationPolicy.rotateCredentials.id %q must be 1-64 characters of A-Z, a-z, 0-9, '.', '_', ':' or '-'", rotation.ID)
	}
	if rotation.Strategy != CredentialRotationStrategyReissue {
		return fmt.Errorf("migrationPolicy.rotateCredentials.strategy %q is unsupported (supported: %q)", rotation.Strategy, CredentialRotationStrategyReissue)
	}
	if err := validateSeedUserList("migrationPolicy.rotateCredentials.users", rotation.Users); err != nil {
		return err
	}
	if !slices.IsSorted(rotation.Users) {
		return fmt.Errorf("migrationPolicy.rotateCredentials.users must be sorted")
	}
	return nil
}

func validRotationID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '-':
		default:
			return false
		}
	}
	return true
}

func validateSeedUsersMigration(migration SeedUsersMigration, desired []string) error {
	if migration.From == nil || migration.To == nil {
		return fmt.Errorf("migrationPolicy.seedUsers.from and .to must be arrays, not null")
	}
	if migration.Strategy != SeedUsersStrategyPreserveExisting {
		return fmt.Errorf("migrationPolicy.seedUsers.strategy %q is unsupported (supported: %q)", migration.Strategy, SeedUsersStrategyPreserveExisting)
	}
	if err := validateSeedUserList("migrationPolicy.seedUsers.from", migration.From); err != nil {
		return err
	}
	if err := validateSeedUserList("migrationPolicy.seedUsers.to", migration.To); err != nil {
		return err
	}
	if slices.Equal(migration.From, migration.To) {
		return fmt.Errorf("migrationPolicy.seedUsers has identical from and to user lists")
	}
	if !slices.Equal(migration.To, desired) {
		return fmt.Errorf("migrationPolicy.seedUsers.to %v does not equal bootstrap.seedUsers %v", migration.To, desired)
	}
	return nil
}

func validateSeedUserList(field string, users []string) error {
	if len(users) == 0 {
		return fmt.Errorf("%s must contain at least one user", field)
	}
	seen := make(map[string]bool, len(users))
	for _, user := range users {
		if user == "" {
			return fmt.Errorf("%s contains an empty user name", field)
		}
		if seen[user] {
			return fmt.Errorf("%s contains duplicate user name %q", field, user)
		}
		seen[user] = true
	}
	return nil
}

func parseCanonicalIPv4Prefix(field, text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s: %w", field, err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s %q is not IPv4", field, text)
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s %q is not a network prefix", field, text)
	}
	return prefix, nil
}

func validateImage(image string) error {
	if strings.TrimSpace(image) != image || image == "" {
		return fmt.Errorf("deployment.image is empty or has surrounding whitespace")
	}
	lastSlash := strings.LastIndexByte(image, '/')
	lastColon := strings.LastIndexByte(image, ':')
	if !strings.Contains(image, "@sha256:") && lastColon <= lastSlash {
		return fmt.Errorf("deployment.image %q has no immutable tag or digest", image)
	}
	if strings.HasSuffix(image, ":latest") {
		return fmt.Errorf("deployment.image must be immutable; :latest is not allowed")
	}
	return nil
}

func validateUniqueProtocols(protocols []profile.Protocol) error {
	known := knownProtocols()
	seen := map[profile.Protocol]bool{}
	for _, protocol := range protocols {
		if !known[protocol] {
			return fmt.Errorf("deployment.protocols.disabled contains unknown protocol %q", protocol)
		}
		if seen[protocol] {
			return fmt.Errorf("deployment.protocols.disabled contains duplicate protocol %q", protocol)
		}
		seen[protocol] = true
	}
	return nil
}

func validateXDPInterfaces(interfaces []string) error {
	seen := map[string]bool{}
	for _, name := range interfaces {
		if name == "" {
			return fmt.Errorf("deployment.xdpInterfaces contains an empty interface")
		}
		if seen[name] {
			return fmt.Errorf("deployment.xdpInterfaces contains duplicate interface %q", name)
		}
		seen[name] = true
	}
	if seen["auto"] && len(interfaces) != 1 {
		return fmt.Errorf("deployment.xdpInterfaces value %q must be used alone", "auto")
	}
	return nil
}

func validateCompleteMaps(deployment Deployment) error {
	if deployment.Ports == nil || deployment.Subnets == nil || deployment.MTU == nil {
		return fmt.Errorf("deployment ports, subnets and mtu must be JSON objects, not null")
	}
	known := knownProtocols()
	for protocol := range deployment.Ports {
		if !known[protocol] {
			return fmt.Errorf("deployment.ports contains unknown protocol %q", protocol)
		}
	}
	for _, protocol := range profile.AllProtocols {
		if deployment.Ports[protocol] == 0 {
			return fmt.Errorf("deployment.ports has no non-zero value for %q", protocol)
		}
	}

	wireguard := map[profile.Protocol]bool{
		profile.AWG2: true, profile.AWG3: true, profile.WGMasque: true, profile.WGWDTT: true,
	}
	for protocol := range deployment.Subnets {
		if !wireguard[protocol] {
			return fmt.Errorf("deployment.subnets contains non-WireGuard protocol %q", protocol)
		}
	}
	for protocol := range deployment.MTU {
		if !wireguard[protocol] {
			return fmt.Errorf("deployment.mtu contains non-WireGuard protocol %q", protocol)
		}
	}
	for protocol := range wireguard {
		prefix, err := netip.ParsePrefix(deployment.Subnets[protocol])
		if err != nil {
			return fmt.Errorf("deployment.subnets[%q]: %w", protocol, err)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("deployment.subnets[%q] %q is not a network prefix", protocol, prefix)
		}
		if deployment.MTU[protocol] == 0 {
			return fmt.Errorf("deployment.mtu has no non-zero value for %q", protocol)
		}
	}
	return nil
}

func validateBot(bot Bot) error {
	if bot.AdminIDs == nil {
		return fmt.Errorf("bot.adminIds must be an array, not null")
	}
	if bot.SubscriptionPort == 0 {
		return fmt.Errorf("bot.subscriptionPort is zero")
	}
	if bot.WDTTConfigDirectory != "" {
		if !filepath.IsAbs(bot.WDTTConfigDirectory) || filepath.Clean(bot.WDTTConfigDirectory) != bot.WDTTConfigDirectory {
			return fmt.Errorf("bot.wdttConfigDirectory must be a clean absolute path")
		}
		if bot.WDTTConfigDirectory == string(filepath.Separator) {
			return fmt.Errorf("bot.wdttConfigDirectory must not be the filesystem root")
		}
	}
	seen := map[int64]bool{}
	for _, id := range bot.AdminIDs {
		if id <= 0 {
			return fmt.Errorf("bot.adminIds contains non-positive Telegram ID %d", id)
		}
		if seen[id] {
			return fmt.Errorf("bot.adminIds contains duplicate Telegram ID %d", id)
		}
		seen[id] = true
	}
	if bot.DynamicIP {
		if bot.PublicHost == "" {
			return fmt.Errorf("bot.dynamicIp requires bot.publicHost: a server whose address changes is reached by a domain")
		}
		if _, err := netip.ParseAddr(bot.PublicHost); err == nil {
			return fmt.Errorf("bot.publicHost %q is an IP address, but bot.dynamicIp says it changes: use a domain kept current by dynamic DNS", bot.PublicHost)
		}
	}
	if bot.Enabled {
		// An empty adminIds is allowed: the bot then has no admin until one is
		// claimed with the one-time code from `spaiter-vpn bot claim-code`.
		if err := bot.TelegramToken.Validate("bot.telegramToken"); err != nil {
			return err
		}
		if bot.PublicHost == "" {
			return fmt.Errorf("bot.enabled requires bot.publicHost: generated clients need an address to dial")
		}
		for field, host := range map[string]string{"bot.publicIpv4Host": bot.PublicIPv4Host, "bot.cdnHost": bot.CDNHost} {
			if host != "" && (strings.ContainsAny(host, ":/ ") || strings.Trim(host, ".") != host) {
				return fmt.Errorf("%s %q must be a bare host name, without a scheme or port", field, host)
			}
		}
		if bot.TelegramAPIURL != "" {
			parsed, err := url.Parse(bot.TelegramAPIURL)
			if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.RawQuery != "" || parsed.User != nil {
				return fmt.Errorf("bot.telegramApiUrl %q must be an http(s) URL with a host and no credentials or query", bot.TelegramAPIURL)
			}
		}
	} else if bot.TelegramToken != "" {
		return fmt.Errorf("bot.telegramToken is set while bot.enabled is false")
	}
	return nil
}

func validateHandshake(field string, handshake Handshake) error {
	if handshake.Host == "" {
		return fmt.Errorf("%s.host is empty", field)
	}
	if handshake.Port == 0 {
		return fmt.Errorf("%s.port is zero", field)
	}
	return nil
}

func (s State) profileSpecForValidation() (profile.Spec, error) {
	return s.profileSpec(placeholderResolver)
}

func (s State) profileSpec(resolve func(SecretRef) (string, error)) (profile.Spec, error) {
	if s.Bootstrap.SeedUsers == nil {
		return profile.Spec{}, fmt.Errorf("bootstrap.seedUsers must be an array, not null")
	}
	spec := profile.Defaults(s.Bootstrap.SeedUsers)
	spec.Tier = s.Deployment.Tier
	spec.Ports = cloneMap(s.Deployment.Ports)
	spec.MTU = cloneMap(s.Deployment.MTU)
	spec.Subnets = make(map[profile.Protocol]netip.Prefix, len(s.Deployment.Subnets))
	for protocol, text := range s.Deployment.Subnets {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return profile.Spec{}, fmt.Errorf("deployment.subnets[%q]: %w", protocol, err)
		}
		spec.Subnets[protocol] = prefix
	}
	spec.Enabled = map[profile.Protocol]bool{}
	for _, protocol := range spec.TierProtocols() {
		spec.Enabled[protocol] = true
	}
	for _, protocol := range s.Deployment.Protocols.Disabled {
		if _, inTier := spec.Enabled[protocol]; !inTier {
			return profile.Spec{}, fmt.Errorf("deployment.protocols.disabled contains %q, which is outside tier %q", protocol, spec.Tier)
		}
		spec.Enabled[protocol] = false
	}

	spec.LogLevel = s.Deployment.LogLevel
	spec.RealityHandshakeServer = s.Deployment.RealityHandshake.Host
	spec.RealityHandshakePort = s.Deployment.RealityHandshake.Port
	spec.ShadowTLSHandshakeServer = s.Deployment.ShadowTLSHandshake.Host
	spec.ShadowTLSHandshakePort = s.Deployment.ShadowTLSHandshake.Port
	spec.MTProtoFrontDomain = s.Deployment.MTProtoFrontDomain
	spec.RetireSharedMTProto = s.Deployment.RetireSharedMTProto
	spec.MTProtoPerUser = s.Deployment.MTProtoPerUser
	// "auto" is resolved by discovery. The profile only needs a syntactically
	// valid value here; no interface is required for config validation.
	if len(s.Deployment.XDPInterfaces) == 1 && s.Deployment.XDPInterfaces[0] == "auto" {
		spec.XDPInterfaces = nil
	} else {
		spec.XDPInterfaces = append([]string(nil), s.Deployment.XDPInterfaces...)
	}

	if err := applyCertificates(&spec, s.Deployment, resolve); err != nil {
		return profile.Spec{}, err
	}
	return spec, nil
}

// PreflightSpec returns the non-secret profile view needed by discovery and
// preflight. DNS credentials are represented by non-secret placeholders, so
// this value must never be passed to profile.Generate.
//
// resolvedXDP is used only when desired state says "auto". Discovery supplies
// the default-route interface; an empty result deliberately leaves XDP
// disabled so the caller can report resolution failure separately.
func (s State) PreflightSpec(resolvedXDP []string) (profile.Spec, error) {
	spec, err := s.profileSpecForValidation()
	if err != nil {
		return profile.Spec{}, err
	}
	if len(s.Deployment.XDPInterfaces) == 1 && s.Deployment.XDPInterfaces[0] == "auto" {
		spec.XDPInterfaces = append([]string(nil), resolvedXDP...)
	}
	return spec, nil
}

// placeholderResolver stands in for the credential store while validating. It
// returns a non-secret marker so a document can be checked without root, and
// is the reason profileSpecForValidation must never be passed to
// profile.Generate: the marker would be written into a live config.
func placeholderResolver(SecretRef) (string, error) { return "credential-present", nil }

// DeploymentSpec returns the profile that bootstrap apply generates from,
// with every credential resolved through the given store.
//
// Separate from PreflightSpec rather than a flag on it: PreflightSpec fills
// credentials with a placeholder so a document can be reviewed unprivileged,
// and the two must not be interchangeable, because generating from a
// placeholder would write "credential-present" into a live config as the
// Cloudflare token and the failure would only surface at the first renewal.
//
// resolvedXDP is used only when desired state says "auto"; apply must pass the
// interface discovery resolved, since an empty list silently disables the
// blocker.
func (s State) DeploymentSpec(resolvedXDP []string, resolve func(SecretRef) (string, error)) (profile.Spec, error) {
	if resolve == nil {
		return profile.Spec{}, fmt.Errorf("DeploymentSpec requires a credential resolver")
	}
	spec, err := s.profileSpec(resolve)
	if err != nil {
		return profile.Spec{}, err
	}
	if len(s.Deployment.XDPInterfaces) == 1 && s.Deployment.XDPInterfaces[0] == "auto" {
		spec.XDPInterfaces = append([]string(nil), resolvedXDP...)
	}
	if err := spec.Validate(); err != nil {
		return profile.Spec{}, fmt.Errorf("deployment profile: %w", err)
	}
	return spec, nil
}

func applyCertificates(spec *profile.Spec, deployment Deployment, resolve func(SecretRef) (string, error)) error {
	needsCertificate := false
	for _, protocol := range spec.EnabledProtocols() {
		if protocol.NeedsCertificate() {
			needsCertificate = true
			break
		}
	}
	if !needsCertificate {
		if deployment.Certificates != nil {
			return fmt.Errorf("deployment.certificates is set but no enabled protocol needs a certificate")
		}
		if deployment.Domain != "" {
			return fmt.Errorf("deployment.domain is set but no enabled protocol needs a certificate")
		}
		return nil
	}

	if deployment.Certificates == nil {
		return fmt.Errorf("deployment.certificates is required by the enabled protocols")
	}
	spec.Domain = deployment.Domain
	certificates := deployment.Certificates
	spec.Certs.Source = certificates.Source

	branches := 0
	if certificates.Files != nil {
		branches++
	}
	if certificates.ACMEHTTP != nil {
		branches++
	}
	if certificates.ACMEDNS != nil {
		branches++
	}
	if branches != 1 {
		return fmt.Errorf("deployment.certificates must contain exactly one source branch")
	}

	switch certificates.Source {
	case profile.CertSourceFiles:
		if certificates.Files == nil {
			return fmt.Errorf("deployment.certificates.source %q requires the files branch", certificates.Source)
		}
		if !filepath.IsAbs(certificates.Files.CertificatePath) || !filepath.IsAbs(certificates.Files.KeyPath) {
			return fmt.Errorf("deployment certificate and key paths must be absolute")
		}
		spec.Certs.CertificatePath = certificates.Files.CertificatePath
		spec.Certs.KeyPath = certificates.Files.KeyPath

	case profile.CertSourceACMEHTTP:
		if certificates.ACMEHTTP == nil {
			return fmt.Errorf("deployment.certificates.source %q requires the acmeHttp branch", certificates.Source)
		}
		if err := applyACMECommon(&spec.Certs, certificates.ACMEHTTP.Email, certificates.ACMEHTTP.Directory, certificates.ACMEHTTP.DataDirectory); err != nil {
			return err
		}
		spec.Certs.AlternativeHTTPPort = certificates.ACMEHTTP.AlternativePort

	case profile.CertSourceACMEDNS:
		if certificates.ACMEDNS == nil {
			return fmt.Errorf("deployment.certificates.source %q requires the acmeDns branch", certificates.Source)
		}
		dns := certificates.ACMEDNS
		if err := applyACMECommon(&spec.Certs, dns.Email, dns.Directory, dns.DataDirectory); err != nil {
			return err
		}
		spec.Certs.DNSProvider = dns.Provider
		switch dns.Provider {
		case C.DNSProviderCloudflare:
			if dns.Cloudflare == nil || dns.Account != nil {
				return fmt.Errorf("cloudflare DNS provider requires only the cloudflare branch")
			}
			if err := dns.Cloudflare.APIToken.Validate("deployment.certificates.acmeDns.cloudflare.apiToken"); err != nil {
				return err
			}
			token, err := resolve(dns.Cloudflare.APIToken)
			if err != nil {
				return err
			}
			spec.Certs.CloudflareAPIToken = token
		case C.DNSProviderACMEDNS:
			if dns.Account == nil || dns.Cloudflare != nil {
				return fmt.Errorf("acmedns provider requires only the account branch")
			}
			if err := dns.Account.Password.Validate("deployment.certificates.acmeDns.account.password"); err != nil {
				return err
			}
			password, err := resolve(dns.Account.Password)
			if err != nil {
				return err
			}
			spec.Certs.ACMEDNSUsername = dns.Account.Username
			spec.Certs.ACMEDNSPassword = password
			spec.Certs.ACMEDNSSubdomain = dns.Account.Subdomain
			spec.Certs.ACMEDNSServerURL = dns.Account.ServerURL
		default:
			return fmt.Errorf("unknown DNS provider %q", dns.Provider)
		}
	default:
		return fmt.Errorf("unknown certificate source %q", certificates.Source)
	}
	return nil
}

func applyACMECommon(certs *profile.TLSCerts, email, directory, dataDirectory string) error {
	if directory == "" {
		return fmt.Errorf("ACME directory/provider is empty; store %q explicitly for the production default", ACMEDefaultProvider)
	}
	if dataDirectory == "" {
		return fmt.Errorf("ACME dataDirectory is empty; store %q explicitly for the deployment default", profile.ACMEDefaultDataDirectory)
	}
	certs.Email = email
	certs.Directory = directory
	certs.DataDirectory = dataDirectory
	return nil
}

func knownProtocols() map[profile.Protocol]bool {
	result := make(map[profile.Protocol]bool, len(profile.AllProtocols))
	for _, protocol := range profile.AllProtocols {
		result[protocol] = true
	}
	return result
}

func sortedProtocolNames(protocols []profile.Protocol) []profile.Protocol {
	result := make([]profile.Protocol, len(protocols))
	copy(result, protocols)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
