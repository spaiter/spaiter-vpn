package deploy

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// BotConfigFileName is the config init writes beside the core's.
const BotConfigFileName = "bot.json"

// DefaultBotImage is the base the bot runs in.
//
// A static-only image: the bot is one static binary and needs nothing from a
// distribution except the CA bundle, which this one carries. No shell, no
// package manager, nothing to be useful with if the process is ever subverted
// -- and this process answers to the open internet.
//
// Not the :nonroot variant, and that is a constraint rather than a preference.
// The core's config.json is owned by root and mode 0600 because it carries
// every private key in the deployment plus the clash API secret, and the bot
// authenticates with that secret -- it reads the file to learn where to connect
// and how. An unprivileged uid cannot open it, so the bot would start and fail
// every request. Loosening the file's mode instead would expose the core's keys
// to anything else in that group, which is the worse trade: the bot is one
// process on a host whose whole point is that file.
const DefaultBotImage = "gcr.io/distroless/static"

// BotBinaryTarget is where the binary is mounted inside the container.
const BotBinaryTarget = "/usr/local/bin/spaiter-vpn"

// Bot configures the provisioning bot's service.
//
// The bot is the same binary as this installer, run with a different
// subcommand. That is not packaging convenience: the generators that render
// client configs and the core's option types are compiled together, so they
// cannot disagree. They did disagree twice while the bot was a separate Python
// program, and both times the symptom was a user whose configuration had
// stopped working.
type Bot struct {
	Enabled bool
	Image   string
	// Binary is the host path to the spaiter-vpn binary the service runs. It
	// must be statically linked, which this repository's builds are: a
	// dynamically linked one finds no loader in the image above.
	Binary string
	// DataDir is the bot's writable state: its token registry, subscription
	// cache, per-user peers and passwords, and the reload markers.
	DataDir string
	// WDTTConfigDirectory is the host directory shared with the external
	// wdtt-relay. The bot sees it at its fixed /wdtt-cfg path and edits only
	// passwords.json inside it.
	WDTTConfigDirectory string
	// AdminIDs are the Telegram accounts allowed to administer it. Without
	// any, nobody does until a one-time claim code is redeemed.
	AdminIDs []int64
	// ControlSocketDir is the host directory holding the control daemon's
	// socket, mounted at the same path. Empty leaves the bot without server
	// administration. The directory rather than the socket, because the
	// daemon recreates the socket on every start.
	ControlSocketDir string
	// User is "uid:gid" for a bot running as its dedicated account. With it,
	// ManagementFile replaces the core's configuration directory: the bot
	// gets the management endpoint and secret, not the deployment's keys.
	User           string
	ManagementFile string
	// TelegramAPIURL is passed through to the bot's configuration.
	TelegramAPIURL string
	// ServiceGID is added to the bot's groups, so a bot running as its own
	// account can reach the control socket and read the web UI's key.
	ServiceGID uint32
	// WebKey and WebURL let admins ask the bot for web UI login links.
	WebKey string
	WebURL string
	// PublicHost is what client configs are told to dial. The same value
	// `clients -host` takes, and for the same reason: the server binds
	// wildcards.
	PublicHost string
	// SubHostCF and SubHostDirect are where the subscription URLs point. The
	// direct one carries a port because on a DS-Lite line there is no inbound
	// :443 to be had.
	SubHostCF     string
	SubHostDirect string
	// PublicIPv4Host and CDNHost replace the bot's built-in defaults, which
	// name the original deployment's hosts; empty means none, not those.
	PublicIPv4Host string
	CDNHost        string
	SubPort        uint16
	// EnableChains and EnableAWG3 add the bundle nodes that older client cores
	// cannot parse. Both default off, and that is the safe direction: a core
	// built before those options landed rejects the WHOLE subscription rather
	// than skipping a node it does not know, so one old client turns a richer
	// bundle into no configuration at all. Turn them on once every client is
	// known to be current.
	EnableChains bool
	EnableAWG3   bool
}

// DefaultBotSubPort is the bot's in-process HTTP server for subscription URLs.
const DefaultBotSubPort = 10873

// ReloadMarkerPath is where the bot asks for a config reload.
//
// This is the whole reason the installer should generate both halves. The bot
// writes a marker and something privileged reacts to it; configured
// independently, those two paths must happen to match. Derived from one place,
// they match by construction — and a mismatch is the kind of failure that looks
// like nothing at all: provisioning appears to work, the marker lands somewhere
// nobody watches, and new users simply never take effect.
func (b Bot) ReloadMarkerPath() string {
	return filepath.Join(b.DataDir, ".reload-singbox")
}

// WDTTReloadMarkerPath is watched by the host integration that sends SIGHUP
// to the externally managed relay after passwords.json changes.
func (b Bot) WDTTReloadMarkerPath() string {
	return filepath.Join(b.DataDir, ".reload-wdtt")
}

// WDTTPasswordsPath is the exact host-side runtime file shared by the bot and
// relay. Empty means this deployment has no external relay path contract.
func (b Bot) WDTTPasswordsPath() string {
	if b.WDTTConfigDirectory == "" {
		return ""
	}
	return filepath.Join(b.WDTTConfigDirectory, "passwords.json")
}

// Config renders the bot's configuration for this deployment.
//
// Built on the defaults rather than from nothing, so a field this installer has
// no opinion about keeps the working value instead of becoming the zero one.
// Everything the compose service and the bot both have to agree on -- the data
// directory, the subscription port, the core's config path -- is derived here,
// in one place.
func (b Bot) Config(p Params) botcfg.Config {
	cfg := botcfg.Defaults()
	cfg.Core.ConfigPath = coreConfigTarget
	cfg.Paths.DataDir = botDataTarget
	cfg.Paths.WDTTConfigDir = wdttConfigTarget
	cfg.Admins = b.AdminIDs
	cfg.TelegramAPIURL = b.TelegramAPIURL
	if b.WebKey != "" && b.WebURL != "" {
		cfg.Web = botcfg.Web{URL: b.WebURL, KeyPath: WebKeyTarget}
	}
	if b.ManagementFile != "" {
		cfg.Core.ManagementPath = managementTarget
	}
	if b.ControlSocketDir != "" {
		cfg.Paths.ControlSocket = filepath.Join(b.ControlSocketDir, ControlSocketName)
	}

	if b.PublicHost != "" {
		cfg.Public.Host = b.PublicHost
	}
	cfg.Public.IPv4Host = b.PublicIPv4Host
	cfg.Public.CDN = nil
	if b.CDNHost != "" {
		cfg.Public.CDN = map[string]botcfg.CDNFront{
			string(profile.VLESSWSCDN): {Host: b.CDNHost, Port: 443, SNI: b.CDNHost},
		}
	}
	cfg.Subscription.HostCF = b.SubHostCF
	cfg.Subscription.HostDirect = b.SubHostDirect
	// Without either the bot hands out a subscription message with no link in
	// it. The direct one follows the public address, so a server that moves
	// hands out the new link without a separate setting to forget.
	if cfg.Subscription.HostDirect == "" && b.PublicHost != "" {
		cfg.Subscription.HostDirect = net.JoinHostPort(b.PublicHost, strconv.Itoa(int(b.subPort())))
	}
	cfg.Subscription.Port = b.subPort()
	cfg.Bundle.EnableChains = b.EnableChains
	cfg.Bundle.EnableAWG3 = b.EnableAWG3
	return cfg
}

// ConfigJSON renders the configuration as the file the service mounts.
func (b Bot) ConfigJSON(p Params) ([]byte, error) {
	data, err := json.MarshalIndent(b.Config(p), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", BotConfigFileName, err)
	}
	return append(data, '\n'), nil
}

// Paths inside the container. Named so the compose entry and the generated
// config cannot drift: both read them from here.
const (
	coreConfigTarget = "/sing-box/config.json"
	botDataTarget    = "/data"
	botConfigTarget  = "/etc/spaiter-vpn/bot.json"
	managementTarget = "/etc/spaiter-vpn/management.json"
	wdttConfigTarget = "/wdtt-cfg"
)

func (b Bot) subPort() uint16 {
	if b.SubPort == 0 {
		return DefaultBotSubPort
	}
	return b.SubPort
}

// composeService renders the bot's compose entry.
func (b Bot) composeService(p Params) string {
	image := b.Image
	if image == "" {
		image = DefaultBotImage
	}

	var s strings.Builder
	fmt.Fprintf(&s, "  %s:\n", BotServiceName)
	fmt.Fprintf(&s, "    image: %s\n", image)
	s.WriteString("    container_name: vpn-bot\n")
	s.WriteString("    restart: always\n")
	if b.User != "" {
		fmt.Fprintf(&s, "    user: %q\n", b.User)
	}
	if b.ServiceGID != 0 {
		fmt.Fprintf(&s, "    group_add: [\"%d\"]\n", b.ServiceGID)
	}
	// The image is a bare base with no entrypoint of its own; the binary is
	// the mounted one. Without this the container looked for a program
	// called "bot" and never started.
	fmt.Fprintf(&s, "    entrypoint: [%q]\n", BotBinaryTarget)
	fmt.Fprintf(&s, "    command: [\"bot\", \"-config\", %q]\n", botConfigTarget)
	// Host networking: the bot serves subscription URLs on a host port that a
	// reverse proxy or tunnel forwards to, and talks to the core's clash API on
	// loopback.
	s.WriteString("    network_mode: host\n")
	// NOT /var/run/docker.sock, and this is load-bearing rather than tidy. A
	// publicly reachable Telegram bot holding the Docker API is effectively root
	// on the host. It asks for a reload by touching a marker file, and the
	// reload sidecar — which needs no Docker access either — acts on it.
	s.WriteString("    environment:\n")
	// The token is referenced, never written. Nothing this installer generates
	// contains it.
	s.WriteString("      - TELEGRAM_TOKEN=${TELEGRAM_TOKEN:?set TELEGRAM_TOKEN before starting the bot}\n")
	s.WriteString("    volumes:\n")
	// Read-only on the core's directory: the bot edits users through the clash
	// API, not by writing the file. sing-box owns that file and rewrites it
	// itself through config_output_path.
	if b.ManagementFile != "" {
		fmt.Fprintf(&s, "      - %s:%s:ro\n", b.ManagementFile, managementTarget)
	} else {
		fmt.Fprintf(&s, "      - %s:/sing-box:ro\n", p.ConfigDir)
	}
	fmt.Fprintf(&s, "      - %s:%s\n", b.DataDir, botDataTarget)
	if b.WDTTConfigDirectory != "" {
		fmt.Fprintf(&s, "      - %s:%s\n", b.WDTTConfigDirectory, wdttConfigTarget)
	}
	if b.ControlSocketDir != "" {
		fmt.Fprintf(&s, "      - %s:%s\n", b.ControlSocketDir, b.ControlSocketDir)
	}
	if b.WebKey != "" {
		fmt.Fprintf(&s, "      - %s:%s:ro\n", b.WebKey, WebKeyTarget)
	}
	fmt.Fprintf(&s, "      - %s:%s:ro\n",
		filepath.Join(p.ConfigDir, BotConfigFileName), botConfigTarget)
	// The binary, mounted rather than baked: the image is a base nobody has to
	// rebuild, and the bot is always the same build as the installer that
	// deployed it.
	fmt.Fprintf(&s, "      - %s:%s:ro\n", b.Binary, BotBinaryTarget)
	s.WriteString("    depends_on:\n")
	s.WriteString("      - sing-box\n")
	return s.String()
}
