package deploy

import (
	"strings"
	"testing"
)

func TestTheControlUnitRunsTheDaemonOnTheFixedSocket(t *testing.T) {
	unit := string(ControlUnit("/opt/vpn/spaiter-vpn"))
	for _, want := range []string{
		"ExecStart=/opt/vpn/spaiter-vpn control serve -socket " + ControlSocketDir + "/" + ControlSocketName,
		"RuntimeDirectory=spaiter-vpn", "NoNewPrivileges=yes", "WantedBy=multi-user.target", "After=docker.service",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	// The binary may live under /tmp or a home directory, so neither is hidden.
	for _, absent := range []string{"PrivateTmp", "ProtectHome"} {
		if strings.Contains(unit, absent) {
			t.Errorf("the control unit sets %s, which could hide the binary it runs", absent)
		}
	}
}

func TestTheWebUnitRunsUnprivilegedAndGetsOnlyItsKey(t *testing.T) {
	plain := string(WebUnit("/opt/vpn/spaiter-vpn", "/etc/spaiter-vpn/web.key", "127.0.0.1:10880", false))
	for _, want := range []string{
		"User=" + WebUserName, "Group=" + ServiceGroup, "LoadCredential=web.key:/etc/spaiter-vpn/web.key",
		"web serve -listen 127.0.0.1:10880 -key ${CREDENTIALS_DIRECTORY}/web.key -socket " + ControlSocketDir + "/" + ControlSocketName,
		"CapabilityBoundingSet=", "ProtectSystem=strict", "After=" + ControlUnitName,
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("unit lacks %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "-secure-cookie") {
		t.Error("the secure-cookie flag is on without being asked for")
	}
	secure := string(WebUnit("/b", "/k", "127.0.0.1:1", true))
	line := strings.Split(secure, "\n")[lineOf(secure, "ExecStart=")]
	if !strings.HasSuffix(line, " -secure-cookie") {
		t.Errorf("the secure-cookie flag is missing from ExecStart: %q", line)
	}
}

func lineOf(text, prefix string) int {
	for i, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return i
		}
	}
	return -1
}

func TestTheDDNSUnitHidesTheDeploymentAndHandsOverOnlyTheToken(t *testing.T) {
	unit := string(DDNSUnit("/opt/vpn/spaiter-vpn", DDNS{
		Provider: "dyndns2", Hosts: []string{"a.example.com", "b.example.com"}, IPv4Hosts: []string{"v4.example.com"},
		CredentialPath: "/etc/spaiter-vpn/credentials/ddns", Username: "me", Server: "https://dyn.example.com/nic/update",
		IPv6: true, CredentialRevision: "rev-7", HiddenPaths: []string{"/etc/spaiter-vpn", "/var/lib/spaiter-vpn"},
	}))
	for _, want := range []string{
		"-provider dyndns2 -host a.example.com,b.example.com", "-ipv4-host v4.example.com", "-username me",
		"-server https://dyn.example.com/nic/update", "-ipv6", "-token-file ${CREDENTIALS_DIRECTORY}/ddns-token",
		"-status " + DDNSStatusPath, "LoadCredential=ddns-token:/etc/spaiter-vpn/credentials/ddns",
		"# Credential revision: rev-7", "InaccessiblePaths=-/etc/spaiter-vpn -/var/lib/spaiter-vpn",
		"CapabilityBoundingSet=", "NoNewPrivileges=yes", "StateDirectory=spaiter-vpn-ddns", "Restart=always",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	// The token's value never appears, only where systemd finds it.
	if strings.Contains(unit, "ddns-token-value") {
		t.Error("a token value leaked into the unit")
	}

	minimal := string(DDNSUnit("/b", DDNS{Provider: "cloudflare", Hosts: []string{"h.example.com"}, CredentialPath: "/c"}))
	for _, absent := range []string{"-ipv4-host", "-username", "-server", "-ipv6"} {
		if strings.Contains(minimal, absent) {
			t.Errorf("an unset option %s was rendered:\n%s", absent, minimal)
		}
	}
}

func TestServicesFollowWhatIsEnabledAndAreFoundInTheRenderedProject(t *testing.T) {
	p := testParams()
	p.Reload.Enabled, p.Bot.Enabled = false, false
	if got := p.Services(); len(got) != 1 || got[0] != CoreServiceName {
		t.Errorf("core only: %v", got)
	}
	full := botParams()
	want := []string{CoreServiceName, ReloadServiceName, BotServiceName}
	if got := full.Services(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("full: %v, want %v in start order", got, want)
	}
	if got := ServicesInProject([]byte(full.Compose())); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("found in the rendered project: %v", got)
	}
	if got := ServicesInProject([]byte(p.Compose())); len(got) != 1 || got[0] != CoreServiceName {
		t.Errorf("found in the core-only project: %v", got)
	}
	// A service that is not ours is never reported, whatever else the file holds.
	if got := ServicesInProject([]byte("services:\n  postgres:\n    image: x\n")); len(got) != 0 {
		t.Errorf("a foreign service was reported: %v", got)
	}
}

func TestTheBotsRuntimeFilesLiveWhereTheRelayLooks(t *testing.T) {
	b := botParams().Bot
	if got := b.WDTTReloadMarkerPath(); got != "/srv/bot-data/.reload-wdtt" {
		t.Errorf("WDTT marker = %q", got)
	}
	if got := b.WDTTPasswordsPath(); got != "/srv/wdtt-relay/passwords.json" {
		t.Errorf("passwords = %q", got)
	}
	b.WDTTConfigDirectory = ""
	if got := b.WDTTPasswordsPath(); got != "" {
		t.Errorf("without a relay the path must be empty, got %q", got)
	}
	if b.subPort() != DefaultBotSubPort {
		t.Errorf("default subscription port = %d", b.subPort())
	}
	b.SubPort = 4321
	if b.subPort() != 4321 {
		t.Errorf("explicit subscription port = %d", b.subPort())
	}
}
