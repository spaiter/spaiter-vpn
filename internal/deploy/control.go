package deploy

import (
	"fmt"
	"strings"
)

// The control daemon's fixed places. The socket's directory is a runtime
// directory systemd creates for the unit.
// BotUserName is the system account the bot runs as when the desired state
// asks for a dedicated user.
const BotUserName = "spaiter-vpn-bot"

// WebUserName is the system account the web UI runs as, and ServiceGroup
// the group that may use the control socket and read the web UI's key.
const (
	WebUserName  = "spaiter-vpn-web"
	ServiceGroup = "spaiter-vpn"
	WebUnitName  = "spaiter-vpn-web.service"
	// WebKeyTarget is where the bot finds the web UI's key.
	WebKeyTarget = "/etc/spaiter-vpn/web.key"
)

// WebUnit renders the web UI's systemd unit. It runs as WebUserName with the
// service group, so it can reach the control socket and read its key, and it
// may hold nothing else.
func WebUnit(binary, keyPath, listen string, secureCookie bool) []byte {
	secure := ""
	if secureCookie {
		secure = " -secure-cookie"
	}
	return []byte(fmt.Sprintf(`# Managed by spaiter-vpn bootstrap (bootstrap.manageWeb).
[Unit]
Description=spaiter-vpn web UI
After=spaiter-vpn-control.service
Wants=spaiter-vpn-control.service

[Service]
User=%s
Group=%s
# The key sits in the root-only configuration directory; systemd reads it and
# hands this service alone a private copy.
LoadCredential=web.key:%s
ExecStart=%s web serve -listen %s -key ${CREDENTIALS_DIRECTORY}/web.key -socket %s/%s%s
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
`, WebUserName, ServiceGroup, keyPath, binary, listen, ControlSocketDir, ControlSocketName, secure))
}

const (
	ControlSocketDir  = "/run/spaiter-vpn"
	ControlSocketName = "control.sock"
	ControlUnitName   = "spaiter-vpn-control.service"
)

// ControlUnit renders the systemd unit for `spaiter-vpn control serve`.
//
// binary is the same host path the bot service mounts: one build serves the
// deployment, its bot and its control plane. No PrivateTmp or ProtectHome:
// that path is wherever the operator ran bootstrap from, often /tmp or a home
// directory, and either would hide the binary from the unit that runs it.
func ControlUnit(binary string) []byte {
	return []byte(fmt.Sprintf(`# Managed by spaiter-vpn bootstrap (bootstrap.manageControl).
[Unit]
Description=spaiter-vpn local control plane
After=docker.service network-online.target
Wants=network-online.target

[Service]
ExecStart=%s control serve -socket %s/%s
Restart=on-failure
RuntimeDirectory=spaiter-vpn
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`, binary, ControlSocketDir, ControlSocketName))
}

const (
	DDNSUnitName = "spaiter-vpn-ddns.service"
	// DDNSStatusPath is where the updater writes each round's result: its
	// StateDirectory, which systemd creates for the dynamic user.
	DDNSStatusPath = "/var/lib/spaiter-vpn-ddns/status.json"
)

// DDNS is what the dynamic DNS unit keeps and with what.
type DDNS struct {
	Provider       string
	Hosts          []string // A, and AAAA with IPv6
	IPv4Hosts      []string // A only
	CredentialPath string   // the token, read by systemd as root
	Username       string   // dyndns2
	Server         string   // dyndns2
	IPv6           bool
	// CredentialRevision changes whenever the token's file is replaced, so a
	// new token restarts the unit. It says nothing about the token itself.
	CredentialRevision string
	// HiddenPaths are made inaccessible to the updater: the deployment's
	// configuration and data roots.
	HiddenPaths []string
}

// DDNSUnit renders the unit for `spaiter-vpn ddns run`.
//
// Not a DynamicUser: that forces a private /tmp, and an account of its own
// cannot traverse an operator's 0750 home, so the binary bootstrap was run
// from, which this unit executes in place like the control daemon's, would be
// out of reach (status 203/EXEC, found by acceptance). It runs as root with
// every capability dropped instead: it cannot override a permission, the
// whole filesystem is read-only but its StateDirectory, and the deployment's
// configuration and data roots, keys included, do not exist for it. The token
// is the one secret it gets, handed over by systemd.
func DDNSUnit(binary string, d DDNS) []byte {
	args := []string{"ddns", "run", "-provider", d.Provider, "-host", strings.Join(d.Hosts, ",")}
	if len(d.IPv4Hosts) > 0 {
		args = append(args, "-ipv4-host", strings.Join(d.IPv4Hosts, ","))
	}
	if d.Username != "" {
		args = append(args, "-username", d.Username)
	}
	if d.Server != "" {
		args = append(args, "-server", d.Server)
	}
	if d.IPv6 {
		args = append(args, "-ipv6")
	}
	args = append(args, "-token-file", "${CREDENTIALS_DIRECTORY}/ddns-token", "-status", DDNSStatusPath)
	hidden := ""
	for _, path := range d.HiddenPaths {
		hidden += " -" + path
	}
	return []byte(fmt.Sprintf(`# Managed by spaiter-vpn bootstrap (ddns).
# Credential revision: %s
[Unit]
Description=spaiter-vpn dynamic DNS updater
After=network-online.target
Wants=network-online.target

[Service]
StateDirectory=spaiter-vpn-ddns
LoadCredential=ddns-token:%s
ExecStart=%s %s
Restart=always
RestartSec=30
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
InaccessiblePaths=%s
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
`, d.CredentialRevision, d.CredentialPath, binary, strings.Join(args, " "), strings.TrimSpace(hidden)))
}
