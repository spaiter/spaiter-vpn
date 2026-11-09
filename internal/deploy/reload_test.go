package deploy

import (
	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func testParams() Params {
	return Params{
		Image:     "registry.example/core:abc123",
		ConfigDir: "/etc/sing-box",
		CacheDir:  "/var/lib/sing-box",
		Reload: Reload{
			Enabled:     true,
			MarkerPath:  "/data/.reload-singbox",
			PollSeconds: 3,
		},
	}
}

// TestSidecarHasNoDockerAccess is the point of the whole design. The host unit
// this replaces ran `docker restart`, which needs the Docker API, and a
// container holding the Docker socket is root on the host. Signalling needs
// only to share the PID namespace. If the socket ever reappears here, the
// sidecar has become more dangerous than the systemd unit it replaced.
func TestSidecarHasNoDockerAccess(t *testing.T) {
	compose := testParams().Compose()
	sidecar := sidecarSection(t, compose)

	for _, forbidden := range []string{
		"docker.sock",
		"/var/run/docker",
		"privileged",
		"cap_add",
	} {
		if strings.Contains(sidecar, forbidden) {
			t.Errorf("the reload sidecar mentions %q; it must not need Docker access or privileges", forbidden)
		}
	}

	for _, required := range []string{
		"pid: service:sing-box",
		"network_mode: none",
		"cap_drop:",
		"- ALL",
		"read_only: true",
	} {
		if !strings.Contains(sidecar, required) {
			t.Errorf("the reload sidecar is missing %q:\n%s", required, sidecar)
		}
	}
}

func TestSidecarMountsAreReadOnlyAndNarrow(t *testing.T) {
	sidecar := sidecarSection(t, testParams().Compose())

	// The marker itself, not its directory: the writer keeps other state there
	// and the sidecar has no reason to see it.
	if !strings.Contains(sidecar, "/data/.reload-singbox:/markers/marker:ro") {
		t.Errorf("the marker is not mounted as a single read-only file:\n%s", sidecar)
	}
	if strings.Contains(sidecar, "/data:/markers") {
		t.Error("the whole marker directory is mounted; mount only the marker file")
	}
	for _, line := range strings.Split(sidecar, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- /") || !strings.Contains(line, ":") {
			continue
		}
		if !strings.HasSuffix(line, ":ro") {
			t.Errorf("sidecar mount is writable: %q", line)
		}
	}
}

func TestComposeOmitsTheSidecarWhenDisabled(t *testing.T) {
	p := testParams()
	p.Reload.Enabled = false
	compose := p.Compose()
	if strings.Contains(compose, "sing-box-reload") {
		t.Error("the sidecar was generated although Reload.Enabled is false")
	}
	// And the main service must be untouched by the feature being off.
	if !strings.Contains(compose, "network_mode: host") || !strings.Contains(compose, "- BPF") {
		t.Error("disabling the sidecar changed the sing-box service")
	}
}

// TestAgentDoesNotReloadOnItsOwnStart guards a subtle one: a reload drops live
// sessions, and the marker is already present on disk when the sidecar starts.
// Without the first-observation guard, every restart of the sidecar — including
// a host reboot — would signal a reload nobody asked for.
func TestAgentDoesNotReloadOnItsOwnStart(t *testing.T) {
	script := testParams().Reload.Script()

	if !strings.Contains(script, "first=1") {
		t.Fatal("the agent has no first-observation guard")
	}
	if !strings.Contains(script, "recorded without reloading") {
		t.Error("the agent does not say that it skipped the initial marker")
	}
	// The guard must sit between observing a change and signalling.
	firstCheck := strings.Index(script, `[ "$first" = "1" ]`)
	kill := strings.Index(script, "kill -HUP")
	if firstCheck < 0 || kill < 0 || firstCheck > kill {
		t.Error("the first-observation guard does not precede the signal")
	}
}

func TestAgentResolvesThePIDRatherThanAssumingOne(t *testing.T) {
	script := testParams().Reload.Script()
	if !strings.Contains(script, "pidof sing-box") {
		t.Error("the agent does not resolve sing-box's pid; assuming PID 1 silently signals whatever init happens to be")
	}
	if !strings.Contains(script, `if [ -z "$pid" ]`) {
		t.Error("the agent does not handle a missing sing-box process, so a misconfigured pid namespace would look like success")
	}
	if !strings.Contains(script, "set -eu") {
		t.Error("the agent does not set -eu")
	}
}

func TestAgentUsesTheConfiguredPollInterval(t *testing.T) {
	p := testParams()
	compose := p.Compose()
	if !strings.Contains(compose, "POLL_SECONDS=3") {
		t.Error("the configured poll interval did not reach the sidecar")
	}

	p.Reload.PollSeconds = 0
	if !strings.Contains(p.Compose(), "POLL_SECONDS=2") {
		t.Errorf("a zero poll interval must fall back to the default %d, not become a busy loop", DefaultPollSeconds)
	}
}

// sidecarSection returns just the sidecar's block, so assertions about it
// cannot accidentally be satisfied by the sing-box service above it — which
// legitimately does carry capabilities and host networking.
func sidecarSection(t *testing.T, compose string) string {
	t.Helper()
	idx := strings.Index(compose, "  sing-box-reload:")
	if idx < 0 {
		t.Fatalf("no reload sidecar in the compose project:\n%s", compose)
	}
	return compose[idx:]
}

func botParams() Params {
	p := testParams()
	p.Bot = Bot{
		Enabled:             true,
		Binary:              "/usr/local/bin/spaiter-vpn",
		DataDir:             "/srv/bot-data",
		WDTTConfigDirectory: "/srv/wdtt-relay",
		AdminIDs:            []int64{111, 222},
		PublicHost:          "vpn.example.com",
		SubHostCF:           "sub.example.com",
		SubHostDirect:       "subd.example.com:10866",
	}
	// What init derives rather than asks for twice.
	p.Reload = Reload{Enabled: true, MarkerPath: p.Bot.ReloadMarkerPath(), PollSeconds: 2}
	return p
}

// TestBotAndSidecarAgreeOnTheMarker is the reason the installer generates both
// halves. The bot writes a marker and the sidecar watches one; configured
// independently they must happen to match, and a mismatch is invisible —
// provisioning appears to succeed, the marker lands where nobody looks, and new
// users never take effect.
func TestBotAndSidecarAgreeOnTheMarker(t *testing.T) {
	p := botParams()
	compose := p.Compose()

	// The bot's DATA_DIR is mounted at /data and it writes
	// /data/.reload-singbox, so the host path must be <DataDir>/.reload-singbox.
	wantHostMarker := "/srv/bot-data/.reload-singbox"
	if p.Bot.ReloadMarkerPath() != wantHostMarker {
		t.Fatalf("marker path is %q, want %q", p.Bot.ReloadMarkerPath(), wantHostMarker)
	}
	if !strings.Contains(compose, wantHostMarker+":/markers/marker:ro") {
		t.Errorf("the sidecar does not watch the path the bot writes:\n%s", sidecarSection(t, compose))
	}
	if !strings.Contains(compose, "/srv/bot-data:/data") {
		t.Errorf("the bot's data directory is not mounted at /data, so DATA_DIR would not resolve")
	}
}

// TestBotServiceHasNoDockerAccess guards the 2026-08-11 hardening. A publicly
// reachable Telegram bot holding the Docker API is effectively root on the
// host; it asks for a reload with a marker file instead.
func TestBotServiceHasNoDockerAccess(t *testing.T) {
	compose := botParams().Compose()
	idx := strings.Index(compose, "  vpn-bot:")
	if idx < 0 {
		t.Fatal("no bot service generated")
	}
	section := compose[idx:]
	for _, forbidden := range []string{"docker.sock", "/var/run/docker", "privileged", "cap_add"} {
		if strings.Contains(section, forbidden) {
			t.Errorf("the bot service mentions %q", forbidden)
		}
	}
}

// TestBotTokenIsReferencedNeverWritten. Everything else the installer emits can
// be read by anyone who can read the directory; the token must not be among it.
func TestBotTokenIsReferencedNeverWritten(t *testing.T) {
	compose := botParams().Compose()
	if !strings.Contains(compose, "TELEGRAM_TOKEN=${TELEGRAM_TOKEN:?") {
		t.Error("the token is not a required interpolation, so compose would start a bot that cannot work")
	}
	// A literal would look like 1234567890:AA... — assert the generator never
	// produces a colon-separated token shape.
	if regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{30,}`).MatchString(compose) {
		t.Fatal("something token-shaped was written into the compose project")
	}
}

func TestBotReadsTheCoreDirectoryReadOnly(t *testing.T) {
	compose := botParams().Compose()
	// The bot changes users through the clash API; sing-box owns config.json
	// and rewrites it itself through config_output_path.
	if !strings.Contains(compose, testParams().ConfigDir+":/sing-box:ro") {
		t.Error("the bot has write access to the core's config directory")
	}
}

func TestComposeOmitsTheBotWhenDisabled(t *testing.T) {
	p := botParams()
	p.Bot.Enabled = false
	if strings.Contains(p.Compose(), "vpn-bot") {
		t.Error("the bot was generated although Bot.Enabled is false")
	}
}

// TestTheBotConfigAgreesWithItsComposeEntry is the claim the ReloadMarkerPath
// comment makes, extended to the rest: every value the two halves must share is
// derived from one place, so they agree by construction.
//
// A mismatch here is the failure that looks like nothing at all. The bot writes
// its state to one directory while the service mounts another, or serves
// subscriptions on a port nothing forwards, and provisioning appears to work
// while nobody can connect.
func TestTheBotConfigAgreesWithItsComposeEntry(t *testing.T) {
	p := botParams()
	compose := p.Bot.composeService(p)

	cfg := p.Bot.Config(p)
	// The paths in the config are the ones inside the container, so each has to
	// appear in the compose entry as the target of a mount.
	for _, pair := range []struct{ what, mount string }{
		{"data directory", cfg.Paths.DataDir},
		{"core config", filepath.Dir(cfg.Core.ConfigPath)},
		{"WDTT relay config", cfg.Paths.WDTTConfigDir},
	} {
		if !strings.Contains(compose, ":"+pair.mount) {
			t.Errorf("the %s %q is in the config but nothing mounts it:\n%s",
				pair.what, pair.mount, compose)
		}
	}
	if got, want := p.Bot.WDTTPasswordsPath(), "/srv/wdtt-relay/passwords.json"; got != want {
		t.Fatalf("WDTT passwords path = %q, want %q", got, want)
	}
	if !strings.Contains(compose, botConfigTarget) {
		t.Error("the compose entry does not mount the config it tells the bot to read")
	}
	if !strings.Contains(compose, p.Bot.Binary) {
		t.Error("the compose entry does not mount the binary it runs")
	}

	// The subscription port is agreed rather than defaulted twice.
	if cfg.Subscription.Port != p.Bot.subPort() {
		t.Errorf("config port %d, service port %d", cfg.Subscription.Port, p.Bot.subPort())
	}
}

// TestTheBotConfigKeepsTheWorkingDefaults: built on the defaults rather than
// from nothing, so a field this installer has no opinion about does not become
// the zero value -- an empty WDTT tag or a zero MTU is a method that silently
// stops working.
func TestTheBotConfigKeepsTheWorkingDefaults(t *testing.T) {
	cfg := botParams().Bot.Config(botParams())

	if cfg.WDTT.Tag == "" || cfg.WDTT.MTU == 0 {
		t.Errorf("the WG-over-VK settings were flattened: %+v", cfg.WDTT)
	}
	if cfg.Tags.AWG == "" || cfg.Tags.MASQUEWG == "" {
		t.Errorf("the endpoint tags were flattened: %+v", cfg.Tags)
	}
	if cfg.UI.Hello == "" || len(cfg.UI.Buttons) == 0 {
		t.Error("the interface texts were flattened, so the bot would show blank buttons")
	}
	if cfg.Intervals.SubRefresh.Build() == 0 {
		t.Error("the refresh interval is zero, which would spin the loop")
	}
}

// TestTheBundleGatesDefaultOff: a core built before those options landed
// rejects the whole subscription rather than skipping a node it does not know,
// so one old client would be left with no configuration at all.
func TestTheBundleGatesDefaultOff(t *testing.T) {
	cfg := botParams().Bot.Config(botParams())
	if cfg.Bundle.EnableChains || cfg.Bundle.EnableAWG3 {
		t.Error("a fresh deployment enables bundle nodes that older clients cannot parse")
	}

	p := botParams()
	p.Bot.EnableChains, p.Bot.EnableAWG3 = true, true
	if enabled := p.Bot.Config(p); !enabled.Bundle.EnableChains || !enabled.Bundle.EnableAWG3 {
		t.Error("asking for them did not turn them on")
	}
}

// TestTheBotConfigIsReadableByTheBot closes the loop: the generated file has to
// load through the bot's own loader, which rejects unknown fields.
func TestTheBotConfigIsReadableByTheBot(t *testing.T) {
	p := botParams()
	data, err := p.Bot.ConfigJSON(p)
	if err != nil {
		t.Fatalf("ConfigJSON: %v", err)
	}

	path := filepath.Join(t.TempDir(), "bot.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := botcfg.Load(path)
	if err != nil {
		t.Fatalf("the generated config does not load: %v\n%s", err, data)
	}
	if loaded.Subscription.Port != p.Bot.subPort() {
		t.Errorf("port survived as %d", loaded.Subscription.Port)
	}
	if loaded.Public.Host != p.Bot.PublicHost {
		t.Errorf("host survived as %q", loaded.Public.Host)
	}
}

// A rendered bot config names only the hosts it was given: the bot's
// defaults once carried the original deployment's, and must never again.
func TestARenderedBotNamesNoHostItWasNotGiven(t *testing.T) {
	p := botParams()
	p.Bot.PublicHost = "vpn.example.org"
	data, err := p.Bot.ConfigJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "vpn.example.org") {
		t.Fatalf("the rendered bot config lost its public host:\n%s", data)
	}
	if cfg := p.Bot.Config(p); cfg.Public.IPv4Host != "" || len(cfg.Public.CDN) != 0 {
		t.Fatalf("hosts that were not given: %#v", cfg.Public)
	}
	p.Bot.PublicIPv4Host, p.Bot.CDNHost = "v4.example.org", "cdn.example.org"
	cfg := p.Bot.Config(p)
	if cfg.Public.IPv4Host != "v4.example.org" || cfg.Public.CDN["vless-ws-cdn-in"].Host != "cdn.example.org" {
		t.Fatalf("public = %#v", cfg.Public)
	}
}
