package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/hostinfo"
	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

type initFlags struct {
	out              string
	cacheDir         string
	users            string
	tier             string
	domain           string
	certSource       string
	certFile         string
	keyFile          string
	acmeEmail        string
	acmeDirectory    string
	acmeStaging      bool
	acmeDataDir      string
	acmeHTTPPort     uint
	dnsProvider      string
	cfTokenFile      string
	disable          string
	ports            string
	xdpInterfaces    string
	realityTarget    string
	shadowTLSTarget  string
	mtprotoFront     string
	logLevel         string
	image            string
	singBoxBinary    string
	secretsPath      string
	bot              bool
	botAdmins        string
	botPublicHost    string
	dynamicIP        bool
	botSubHostCF     string
	botSubHostDirect string
	botSubPort       uint
	botDataDir       string
	reloadMarker     string
	reloadPoll       int
	skipCheck        bool
	skipPreflight    bool
	strict           bool
	force            bool
	printSecrets     bool
	// checkOnly marks a spec built for preflight, which inspects the host
	// rather than generating anything and so needs no credentials.
	checkOnly bool
}

func runInit(ctx context.Context, out io.Writer, args []string) error {
	var f initFlags
	fs := newFlagSet("init", out)
	fs.StringVar(&f.out, "out", "/etc/sing-box", "directory to write config.json, secrets.json, .env and docker-compose.yml into")
	fs.StringVar(&f.cacheDir, "cache-dir", "", "host directory mounted at /var/lib/sing-box (default: <out>/../cache)")
	fs.StringVar(&f.users, "users", "", "comma-separated client names (required)")
	fs.StringVar(&f.tier, "tier", string(profile.TierA), "which protocols to generate: a (no domain needed) or ab (also the TLS ones)")
	fs.StringVar(&f.domain, "domain", "", "domain for the Tier B protocols; must already resolve to this host")
	fs.StringVar(&f.certSource, "cert-source", "", "where Tier B's certificates come from: files, acme-http or acme-dns")
	fs.StringVar(&f.certFile, "cert-file", "", "certificate chain, for -cert-source=files")
	fs.StringVar(&f.keyFile, "key-file", "", "private key, for -cert-source=files")
	fs.StringVar(&f.acmeEmail, "acme-email", "", "ACME account contact; without it there is no warning when renewal breaks")
	fs.StringVar(&f.acmeDirectory, "acme-directory", "", "ACME endpoint (default: Let's Encrypt production)")
	fs.BoolVar(&f.acmeStaging, "acme-staging", false, "use Let's Encrypt staging; do this first — production limits failed authorisations to about five per hour")
	fs.StringVar(&f.acmeDataDir, "acme-data-dir", "", "where the ACME account key and certificates persist (default: "+profile.ACMEDefaultDataDirectory+")")
	fs.UintVar(&f.acmeHTTPPort, "acme-http-port", 0, "move the HTTP-01 listener off port 80; only useful when something forwards 80 here")
	fs.StringVar(&f.dnsProvider, "dns-provider", "", "DNS-01 provider for -cert-source=acme-dns: cloudflare or acmedns")
	// Deliberately a file or the environment, never a flag value. A token on
	// the command line is visible in `ps` to every user on the host and lands
	// in the shell history, and this one authorises DNS changes for an entire
	// zone.
	fs.StringVar(&f.cfTokenFile, "cf-token-file", "", "file holding the Cloudflare API token (default: the CLOUDFLARE_API_TOKEN environment variable)")
	fs.StringVar(&f.disable, "disable", "", "comma-separated protocol tags to leave out")
	fs.StringVar(&f.ports, "ports", "", "override ports as tag=port[,tag=port]")
	fs.StringVar(&f.xdpInterfaces, "xdp-interface", "", "host interfaces for the XDP blocker (default: the default-route interface; \"none\" disables it)")
	fs.StringVar(&f.realityTarget, "reality-handshake", "", "host:port whose TLS handshake Reality borrows")
	fs.StringVar(&f.shadowTLSTarget, "shadowtls-handshake", "", "host:port that shadowtls fronts")
	fs.StringVar(&f.mtprotoFront, "mtproto-front", "", "domain encoded in the MTProto fake-TLS secret")
	fs.StringVar(&f.logLevel, "log-level", "", "sing-box log level")
	fs.StringVar(&f.image, "image", singbox.DefaultImage, "sing-box container image")
	fs.StringVar(&f.singBoxBinary, "sing-box", "", "path to a local sing-box binary to validate with instead of the image")
	fs.StringVar(&f.secretsPath, "secrets", "", "where to write the client credentials (default: <out>/secrets/secrets.json)")
	fs.BoolVar(&f.bot, "bot", false, "also deploy the Telegram provisioning bot (needs TELEGRAM_TOKEN in the environment at `up` time)")
	fs.StringVar(&f.botAdmins, "bot-admins", "", "comma-separated Telegram user IDs allowed to administer the bot; empty means the first /start wins")
	fs.StringVar(&f.botPublicHost, "bot-public-host", "", "host the bot tells clients to dial (default: -host if given)")
	fs.BoolVar(&f.dynamicIP, "dynamic-ip", false, "the server's public IP changes; -bot-public-host must then be a domain kept current by dynamic DNS")
	fs.StringVar(&f.botSubHostCF, "bot-sub-host", "", "hostname serving subscription URLs through a CDN or tunnel")
	fs.StringVar(&f.botSubHostDirect, "bot-sub-host-direct", "", "host:port serving subscription URLs directly")
	fs.UintVar(&f.botSubPort, "bot-sub-port", uint(deploy.DefaultBotSubPort), "port the bot serves subscription URLs on")
	fs.StringVar(&f.botDataDir, "bot-data-dir", "", "the bot's writable state (default: <out>/../bot-data)")
	fs.StringVar(&f.reloadMarker, "reload-marker", "", "host path a provisioning bot touches to request a config reload; generates a sidecar that signals sing-box (empty: no sidecar)")
	fs.IntVar(&f.reloadPoll, "reload-poll", deploy.DefaultPollSeconds, "how often the reload sidecar reads the marker's mtime, in seconds")
	fs.BoolVar(&f.skipCheck, "skip-check", false, "install without running sing-box check (not recommended; see -h output)")
	fs.BoolVar(&f.skipPreflight, "skip-preflight", false, "do not check the host before generating")
	fs.BoolVar(&f.strict, "strict", false, "treat preflight warnings as failures")
	fs.BoolVar(&f.force, "force", false, "overwrite an existing config")
	fs.BoolVar(&f.printSecrets, "print-secrets", false, "also print the client credentials to stdout")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn init -users alice,bob [flags]\n\n")
		fmt.Fprintf(out, "Generates every key the server needs and writes a validated config.\n")
		fmt.Fprintf(out, "Protocol tags for -disable, tier a: %s\n", joinProtocols(profile.TierAProtocols))
		fmt.Fprintf(out, "Additional tags with -tier=ab:      %s\n\n", joinProtocols(profile.TierBProtocols))
		fmt.Fprintf(out, "Tier ab needs -domain and -cert-source. Which source is possible depends on the\n")
		fmt.Fprintf(out, "host, not on preference:\n")
		fmt.Fprintf(out, "  acme-dns   the core renews; needs a zone API token. The only one that works\n")
		fmt.Fprintf(out, "             behind carrier-grade NAT or DS-Lite, where there is no inbound :80.\n")
		fmt.Fprintf(out, "  acme-http  the core renews; needs inbound port 80 reachable from the CA.\n")
		fmt.Fprintf(out, "  files      somebody else renews. Note the core caches the chain it read at\n")
		fmt.Fprintf(out, "             startup, so a renewal it is not told about is served stale.\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(out, "\n-skip-check exists for air-gapped hosts only. The generator cannot tell\n")
		fmt.Fprintf(out, "whether a value the schema allows is one sing-box will actually start with,\n")
		fmt.Fprintf(out, "so skipping the check moves that discovery to the first restart.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	spec, err := specFromFlags(f)
	if err != nil {
		return err
	}
	subPortGiven := false
	fs.Visit(func(fl *flag.Flag) { subPortGiven = subPortGiven || fl.Name == "bot-sub-port" })
	in := newPrompt()
	if f.bot {
		// Only the bot hands out client configs, so only it needs to know
		// what clients dial.
		address, err := choosePublicAddress(ctx, in, out, f.botPublicHost, f.dynamicIP, false)
		if err != nil {
			return err
		}
		f.botPublicHost = address.host
	}
	if err := chooseInitPorts(in, out, &spec, &f, subPortGiven); err != nil {
		return err
	}

	cacheDir := resolveCacheDir(f.out, f.cacheDir)
	if err := runPreflightForInit(ctx, out, f, spec, cacheDir); err != nil {
		return err
	}

	configPath := filepath.Join(f.out, "config.json")
	// NOT beside config.json. The service runs with `-C <dir>`, which parses
	// every top-level *.json in that directory and merges them as config
	// fragments, so a secrets bundle there is read as configuration and kills
	// the service at startup with `unknown field "ClashAPISecret"`. A
	// subdirectory is safe: the loader skips directories.
	secretsPath := f.secretsPath
	if secretsPath == "" {
		secretsPath = filepath.Join(f.out, "secrets", "secrets.json")
	}
	if !f.force {
		for _, path := range []string{configPath, secretsPath} {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists; refusing to overwrite a live deployment's keys without -force", path)
			}
		}
	}

	rendered, err := profile.Render(ctx, spec)
	if err != nil {
		return err
	}

	if err := validateConfig(ctx, out, f, rendered.ConfigJSON); err != nil {
		return err
	}

	if err := os.MkdirAll(f.out, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", f.out, err)
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", cacheDir, err)
	}

	// 0600 on both files: between them they hold every private key, user
	// credential and the clash API secret, which is a remote-control channel
	// for the running server.
	if err := config.Write(configPath, rendered.ConfigJSON, 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(secretsPath), 0o700); err != nil {
		return fmt.Errorf("create the secrets directory: %w", err)
	}
	if err := config.Write(secretsPath, rendered.SecretsJSON, 0o600); err != nil {
		return err
	}

	botDataDir := f.botDataDir
	if botDataDir == "" {
		botDataDir = filepath.Join(filepath.Dir(filepath.Clean(f.out)), "bot-data")
	}
	botAdmins, err := parseIDList(f.botAdmins)
	if err != nil {
		return fmt.Errorf("%w: -bot-admins: %w", ErrUsage, err)
	}
	// The bot is this binary, so the service has to be pointed at wherever the
	// operator is running it from.
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary for the bot service: %w", err)
	}
	botCfg := deploy.Bot{
		Enabled:       f.bot,
		Binary:        selfPath,
		DataDir:       mustAbs(botDataDir),
		AdminIDs:      botAdmins,
		PublicHost:    f.botPublicHost,
		SubHostCF:     f.botSubHostCF,
		SubHostDirect: f.botSubHostDirect,
		SubPort:       uint16(f.botSubPort),
	}

	// The reload marker is derived from the bot's data directory rather than
	// configured twice. The bot writes a marker and the sidecar watches one; if
	// those two paths are set independently they must happen to agree, and when
	// they do not the failure is silent — provisioning looks like it worked,
	// the marker lands where nobody watches, and new users never take effect.
	reloadMarker := f.reloadMarker
	if reloadMarker == "" && botCfg.Enabled {
		reloadMarker = botCfg.ReloadMarkerPath()
	}

	params := deploy.Params{
		Image:         f.image,
		ConfigDir:     mustAbs(f.out),
		CacheDir:      mustAbs(cacheDir),
		XDPInterfaces: spec.XDPInterfaces,
		Reload: deploy.Reload{
			Enabled:     reloadMarker != "",
			MarkerPath:  mustAbs(reloadMarker),
			PollSeconds: f.reloadPoll,
		},
		Bot: botCfg,
	}
	artifacts, err := deploy.Render(params)
	if err != nil {
		return err
	}
	var reloadScriptPath string
	if artifacts.ReloadAgent != nil {
		// The marker has to exist before compose starts: a bind mount of a
		// missing path makes Docker create a DIRECTORY there, after which the
		// bot's attempt to write a file fails and reloads silently stop
		// working.
		if err := ensureMarkerFile(params.Reload.MarkerPath); err != nil {
			return err
		}
		reloadScriptPath = filepath.Join(f.out, artifacts.ReloadAgent.Name)
		if err := config.Write(reloadScriptPath, artifacts.ReloadAgent.Data, artifacts.ReloadAgent.Mode); err != nil {
			return err
		}
	}
	if params.Bot.Enabled {
		if err := os.MkdirAll(params.Bot.DataDir, 0o700); err != nil {
			return fmt.Errorf("create the bot's data directory: %w", err)
		}
		// The bot's own config, derived from the same values the compose entry
		// uses, so the two cannot disagree about where the data directory is or
		// which port serves subscriptions.
		if err := config.Write(filepath.Join(f.out, artifacts.BotConfig.Name), artifacts.BotConfig.Data, artifacts.BotConfig.Mode); err != nil {
			return err
		}
	}
	composePath := filepath.Join(f.out, artifacts.Compose.Name)
	if err := config.Write(composePath, artifacts.Compose.Data, artifacts.Compose.Mode); err != nil {
		return err
	}
	envPath := filepath.Join(f.out, artifacts.Environment.Name)
	if err := config.Write(envPath, artifacts.Environment.Data, artifacts.Environment.Mode); err != nil {
		return err
	}
	// Emitted rather than applied. A firewall change is the classic way to
	// lock yourself out of a machine you are halfway through setting up, so
	// the operator reads this before running it. 0755 because it is meant to
	// be run; it contains no secret, only port numbers.
	fwRules := firewall.Rules(spec)
	fwBackend := firewall.Detect()
	fwStatus, fwErr := fwBackend.Check(fwRules)
	if fwErr != nil {
		fwStatus = nil
	}
	fwPath := filepath.Join(f.out, "firewall.sh")
	if err := config.Write(fwPath, []byte(firewall.Script(fwBackend, fwRules, fwStatus)), 0o755); err != nil {
		return err
	}
	// The core has no log rotation and its log is append-only, so at debug
	// level it grows until the disk fills — which takes the server down.
	rotatePath := filepath.Join(f.out, artifacts.Logrotate.Name)
	if err := config.Write(rotatePath, artifacts.Logrotate.Data, artifacts.Logrotate.Mode); err != nil {
		return err
	}

	fmt.Fprintf(out, "wrote %s (0600)\n", configPath)
	fmt.Fprintf(out, "wrote %s (0600) — client credentials, keep it private\n", secretsPath)
	fmt.Fprintf(out, "wrote %s\n", composePath)
	fmt.Fprintf(out, "wrote %s\n", envPath)
	fmt.Fprintf(out, "wrote %s (0755) — %d ports, read it before running it\n", fwPath, len(fwRules))
	fmt.Fprintf(out, "wrote %s — copy to /etc/logrotate.d/ or the log grows until the disk fills\n", rotatePath)
	if reloadScriptPath != "" {
		fmt.Fprintf(out, "wrote %s (0755) — reload sidecar, no Docker access needed\n", reloadScriptPath)
	}
	if err := verifyConfigDirectory(ctx, out, f); err != nil {
		return err
	}

	fmt.Fprintf(out, "\n%d protocols, %d users\n", len(spec.EnabledProtocols()), len(spec.Users))
	for _, p := range spec.EnabledProtocols() {
		fmt.Fprintf(out, "  %-16s port %d\n", p, spec.Ports[p])
	}
	if len(spec.XDPInterfaces) == 0 {
		warn("the XDP blocker is disabled, so a BitTorrent detection drops the connection but does not ban the client")
	}
	if params.Bot.Enabled {
		fmt.Fprintf(out, "wrote %s — the bot runs this same binary with the `bot` subcommand\n",
			filepath.Join(f.out, deploy.BotConfigFileName))
		fmt.Fprintf(out, "\nThe bot needs its token in the environment at start:\n")
		fmt.Fprintf(out, "  TELEGRAM_TOKEN=... spaiter-vpn up -dir %s\n", f.out)
		fmt.Fprintf(out, "Nothing generated here contains it.\n")
		if len(params.Bot.AdminIDs) == 0 {
			warn("no -bot-admins given: whoever sends /start first becomes the administrator")
		}
	}
	fmt.Fprintf(out, "\nNext: spaiter-vpn up -dir %s\n", f.out)

	if f.printSecrets {
		fmt.Fprintf(out, "\n%s", renderSecrets(rendered.Bundle.Secrets))
	}
	return nil
}

// verifyConfigDirectory re-checks the directory the way the service loads it.
//
// The earlier check validated config.json on its own, which is not the same
// question. The service runs with `-C <dir>` and merges every top-level *.json
// it finds, so a stray file next to the config is configuration as far as
// sing-box is concerned. Checking the file but not the directory is how a
// deployment passes validation and then fails to start.
func verifyConfigDirectory(ctx context.Context, out io.Writer, f initFlags) error {
	if f.skipCheck {
		return nil
	}
	checker, err := singbox.Detect(ctx, f.singBoxBinary, f.image)
	if err != nil {
		// Already reported by the pre-write check; nothing new to say.
		return nil
	}
	if err := checker.CheckDirectory(ctx, f.out); err != nil {
		return fmt.Errorf("the written directory does not load: %w", err)
	}
	fmt.Fprintln(out, "sing-box check -C: ok (the directory loads as the service will read it)")
	return nil
}

// ensureMarkerFile creates the marker as an empty file if it is absent.
//
// This is not tidiness. Docker bind-mounts a missing source path by creating a
// directory at it, and a directory where the bot expects to write a file means
// reloads stop working with no error anywhere obvious.
func ensureMarkerFile(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory; the reload marker must be a file (a previous run with no marker present likely let Docker create it)", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create the marker's directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("create the reload marker %s: %w", path, err)
	}
	return file.Close()
}

// runPreflightForInit checks the host before anything is generated.
//
// It runs first, before the keys exist: there is no point minting a
// deployment's worth of private keys to then discover the ports are taken.
func runPreflightForInit(ctx context.Context, out io.Writer, f initFlags, spec profile.Spec, cacheDir string) error {
	if f.skipPreflight {
		warn("-skip-preflight: the host was not checked")
		return nil
	}
	report := preflight.Run(ctx, preflight.Options{
		Spec:          spec,
		ConfigDir:     f.out,
		CacheDir:      cacheDir,
		Image:         f.image,
		SingBoxBinary: f.singBoxBinary,
	})
	if err := report.Err(f.strict); err != nil {
		report.Write(out)
		return fmt.Errorf("%w\n\nFix the failures above, or pass -skip-preflight to generate anyway", err)
	}
	// On success only the imperfect findings are worth the operator's
	// attention; a wall of PASS lines trains people to stop reading them.
	if report.Count(preflight.Warn) > 0 || report.Count(preflight.Unknown) > 0 {
		report.Write(out)
	} else {
		fmt.Fprintf(out, "preflight: %d checks passed\n", report.Count(preflight.Pass))
	}
	return nil
}

// validateConfig runs the mandatory post-generation check.
func validateConfig(ctx context.Context, out io.Writer, f initFlags, configData []byte) error {
	if f.skipCheck {
		warn("-skip-check: the generated config was NOT validated by sing-box")
		return nil
	}
	checker, err := singbox.Detect(ctx, f.singBoxBinary, f.image)
	if err != nil {
		if errors.Is(err, singbox.ErrUnavailable) {
			return fmt.Errorf("%w\n\nValidation is not optional: pass -sing-box <path> to use a local binary, "+
				"or -skip-check to install an unvalidated config deliberately", err)
		}
		return err
	}
	fmt.Fprintf(out, "validating with %s ...\n", checker.Describe())
	if err := checker.Check(ctx, configData); err != nil {
		return fmt.Errorf("the generated config is not usable: %w", err)
	}
	fmt.Fprintln(out, "sing-box check: ok")
	return nil
}

func specFromFlags(f initFlags) (profile.Spec, error) {
	users := splitList(f.users)
	if len(users) == 0 {
		return profile.Spec{}, fmt.Errorf("%w: -users is required; every Tier A protocol is authenticated, so a server with no users accepts nobody", ErrUsage)
	}

	spec := profile.Defaults(users)
	spec.Tier = profile.Tier(f.tier)
	if err := applyCertFlags(f, &spec); err != nil {
		return profile.Spec{}, err
	}

	// The candidate set follows the tier, so -disable names the tier's own
	// protocols rather than Tier A's regardless of what was selected.
	candidates := spec.TierProtocols()
	if disabled := splitList(f.disable); len(disabled) > 0 {
		spec.Enabled = map[profile.Protocol]bool{}
		for _, p := range candidates {
			spec.Enabled[p] = true
		}
		for _, name := range disabled {
			p := profile.Protocol(name)
			if _, known := spec.Enabled[p]; !known {
				return profile.Spec{}, fmt.Errorf("%w: unknown protocol %q; known tags for tier %q are %s", ErrUsage, name, spec.Tier, joinProtocols(candidates))
			}
			delete(spec.Enabled, p)
			spec.Enabled[p] = false
		}
	}

	for _, assignment := range splitList(f.ports) {
		name, portText, found := strings.Cut(assignment, "=")
		if !found {
			return profile.Spec{}, fmt.Errorf("%w: -ports takes tag=port pairs, got %q", ErrUsage, assignment)
		}
		p := profile.Protocol(strings.TrimSpace(name))
		if _, known := spec.Ports[p]; !known {
			return profile.Spec{}, fmt.Errorf("%w: unknown protocol %q in -ports; known tags are %s", ErrUsage, name, joinProtocols(candidates))
		}
		port, err := parsePort(portText)
		if err != nil {
			return profile.Spec{}, fmt.Errorf("%w: -ports %s: %v", ErrUsage, assignment, err)
		}
		spec.Ports[p] = port
	}

	switch f.xdpInterfaces {
	case "none":
		spec.XDPInterfaces = nil
	case "":
		iface, err := hostinfo.DefaultRouteInterface()
		if err != nil {
			return profile.Spec{}, fmt.Errorf("cannot determine the interface for the XDP blocker: %w; "+
				"pass -xdp-interface <name>, or -xdp-interface none to run without it", err)
		}
		spec.XDPInterfaces = []string{iface}
	default:
		spec.XDPInterfaces = splitList(f.xdpInterfaces)
	}

	if f.realityTarget != "" {
		host, port, err := splitHostPort(f.realityTarget, 443)
		if err != nil {
			return profile.Spec{}, fmt.Errorf("-reality-handshake: %w", err)
		}
		spec.RealityHandshakeServer, spec.RealityHandshakePort = host, port
	}
	if f.shadowTLSTarget != "" {
		host, port, err := splitHostPort(f.shadowTLSTarget, 443)
		if err != nil {
			return profile.Spec{}, fmt.Errorf("-shadowtls-handshake: %w", err)
		}
		spec.ShadowTLSHandshakeServer, spec.ShadowTLSHandshakePort = host, port
	}
	if f.mtprotoFront != "" {
		spec.MTProtoFrontDomain = f.mtprotoFront
	}
	if f.logLevel != "" {
		spec.LogLevel = f.logLevel
	}
	return spec, nil
}

// splitHostPort accepts "host" or "host:port". net.SplitHostPort is not used
// because a bare hostname is the common case and it rejects that.
func splitHostPort(value string, defaultPort uint16) (string, uint16, error) {
	host, portText, found := strings.Cut(value, ":")
	if host == "" {
		return "", 0, fmt.Errorf("%q has no host part", value)
	}
	if !found {
		return host, defaultPort, nil
	}
	port, err := parsePort(portText)
	if err != nil {
		return "", 0, fmt.Errorf("%q: %w", value, err)
	}
	return host, port, nil
}

func parsePort(text string) (uint16, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number in 1..65535", text)
	}
	if value == 0 {
		return 0, fmt.Errorf("port 0 is not a port")
	}
	return uint16(value), nil
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parseIDList reads a comma-separated list of Telegram ids.
//
// Validated here rather than carried as text, because an id that is not a
// number is an admin who silently never gets the role: the bot compares
// numbers, and nothing would report the mismatch.
func parseIDList(value string) ([]int64, error) {
	var out []int64
	for _, item := range splitList(value) {
		id, err := strconv.ParseInt(item, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a Telegram id", item)
		}
		out = append(out, id)
	}
	return out, nil
}

func joinProtocols(list []profile.Protocol) string {
	names := make([]string, len(list))
	for i, p := range list {
		names[i] = string(p)
	}
	return strings.Join(names, ", ")
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func renderSecrets(s profile.Secrets) string {
	var b strings.Builder
	b.WriteString("=== client credentials ===\n")
	if s.Reality.PublicKey != "" {
		fmt.Fprintf(&b, "reality public key: %s\n", s.Reality.PublicKey)
		fmt.Fprintf(&b, "reality short_id:   %s\n", s.Reality.ShortID)
	}
	if s.MTProto.Secret != "" {
		fmt.Fprintf(&b, "mtproto secret:     %s (front %s)\n", s.MTProto.Secret, s.MTProto.FrontDomain)
	}
	if s.Shadowsocks.Password != "" {
		fmt.Fprintf(&b, "shadowsocks:        %s / %s\n", s.Shadowsocks.Method, s.Shadowsocks.Password)
	}
	if s.Snell.PSK != "" {
		fmt.Fprintf(&b, "snell psk:          %s (v%d)\n", s.Snell.PSK, s.Snell.Version)
	}
	for _, user := range s.Users {
		fmt.Fprintf(&b, "\n--- %s ---\n", user.Name)
		fmt.Fprintf(&b, "  vless reality uuid: %s\n", user.VLESSRealityUUID)
		fmt.Fprintf(&b, "  vless ws uuid:      %s\n", user.VLESSWSCDNUUID)
		fmt.Fprintf(&b, "  shadowtls password: %s\n", user.ShadowTLSPassword)
		fmt.Fprintf(&b, "  snell userkey:      %s\n", user.SnellUserKey)
		fmt.Fprintf(&b, "  mieru password:     %s\n", user.MieruPassword)
		for _, p := range []profile.Protocol{profile.AWG2, profile.AWG3, profile.WGMasque, profile.WGWDTT} {
			peer, ok := user.Peers[p]
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "  %-13s %s  key %s\n", string(p)+":", peer.Address, peer.PrivateKey)
		}
	}
	return b.String()
}

// chooseInitPorts draws random ports for every protocol -ports did not name,
// and for the bot's subscription server unless -bot-sub-port did, then lets
// the operator review the ones that will listen. See chooseDocumentPorts.
func chooseInitPorts(in *bufio.Reader, out io.Writer, spec *profile.Spec, f *initFlags, subPortGiven bool) error {
	fixed := map[profile.Protocol]bool{}
	for _, assignment := range splitList(f.ports) {
		name, _, _ := strings.Cut(assignment, "=")
		fixed[profile.Protocol(strings.TrimSpace(name))] = true
	}
	var draw []profile.Protocol
	taken := map[uint16]bool{}
	for p, port := range spec.Ports {
		if fixed[p] {
			taken[port] = true
		} else {
			draw = append(draw, p)
		}
	}
	if subPortGiven {
		taken[uint16(f.botSubPort)] = true
	} else {
		draw = append(draw, profile.Protocol(subscriptionPortName))
	}
	drawn, err := profile.RandomPorts(nil, draw, taken)
	if err != nil {
		return err
	}
	for p, port := range drawn {
		if p == profile.Protocol(subscriptionPortName) {
			f.botSubPort = uint(port)
			continue
		}
		spec.Ports[p] = port
	}

	items := protocolPortItems(spec.EnabledProtocols(), spec.Ports, fixed)
	if f.bot {
		items = append(items, portItem{name: "bot " + subscriptionPortName, networks: "tcp", port: uint16(f.botSubPort), fixed: subPortGiven})
	}
	if err := choosePorts(in, out, items); err != nil {
		return err
	}
	for _, item := range items {
		if item.name == "bot "+subscriptionPortName {
			f.botSubPort = uint(item.port)
		} else {
			spec.Ports[profile.Protocol(item.name)] = item.port
		}
	}
	return nil
}
