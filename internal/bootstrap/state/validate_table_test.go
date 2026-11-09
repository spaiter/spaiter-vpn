package state

import (
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func tierB() State {
	s := Default([]string{"alice"})
	s.Deployment.Tier = profile.TierB
	s.Deployment.Domain = "vpn.example.com"
	return s
}

func withACMEDNS(mutate func(*ACMEDNS)) State {
	s := tierB()
	dns := &ACMEDNS{
		Directory: ACMEDefaultProvider, DataDirectory: profile.ACMEDefaultDataDirectory,
		Provider: "cloudflare", Cloudflare: &CloudflareDNS{APIToken: "cloudflare-token"},
	}
	if mutate != nil {
		mutate(dns)
	}
	s.Deployment.Certificates = &Certificates{Source: profile.CertSourceACMEDNS, ACMEDNS: dns}
	return s
}

func enabledBot(mutate func(*Bot)) State {
	s := Default([]string{"alice"})
	s.Bot.Enabled = true
	s.Bot.AdminIDs = []int64{1}
	s.Bot.PublicHost = "vpn.example.com"
	s.Bot.TelegramToken = "telegram-token"
	if mutate != nil {
		mutate(&s.Bot)
	}
	return s
}

// Every refusal names the field that is wrong, because the operator edits a
// JSON document by hand and "invalid state" would send them hunting.
func TestValidateNamesTheFieldThatIsWrong(t *testing.T) {
	cases := []struct {
		name  string
		state State
		want  string // empty: valid
	}{
		{"default", Default([]string{"a"}), ""},
		{"valid bot", enabledBot(nil), ""},
		{"valid acme dns with cloudflare", withACMEDNS(nil), ""},

		{"duplicate disabled protocol", func() State {
			s := Default([]string{"a"})
			s.Deployment.Protocols.Disabled = []profile.Protocol{profile.AWG2, profile.AWG2}
			return s
		}(), "duplicate protocol"},
		{"empty xdp interface", func() State { s := Default([]string{"a"}); s.Deployment.XDPInterfaces = []string{""}; return s }(), "empty interface"},
		{"duplicate xdp interface", func() State {
			s := Default([]string{"a"})
			s.Deployment.XDPInterfaces = []string{"eth0", "eth0"}
			return s
		}(), "duplicate interface"},
		{"unknown port protocol", func() State { s := Default([]string{"a"}); s.Deployment.Ports["nope"] = 1; return s }(), "unknown protocol"},
		{"subnets on a non-wireguard protocol", func() State {
			s := Default([]string{"a"})
			s.Deployment.Subnets[profile.Protocol("vless-reality-in")] = "10.1.0.0/24"
			return s
		}(), "non-WireGuard"},
		{"mtu on a non-wireguard protocol", func() State {
			s := Default([]string{"a"})
			s.Deployment.MTU[profile.Protocol("vless-reality-in")] = 1280
			return s
		}(), "non-WireGuard"},
		{"subnet that is not a prefix", func() State {
			s := Default([]string{"a"})
			s.Deployment.Subnets[profile.AWG2] = "10.40.0.5/24"
			return s
		}(), "not a network prefix"},
		{"subnet that does not parse", func() State { s := Default([]string{"a"}); s.Deployment.Subnets[profile.AWG2] = "banana"; return s }(), "subnets"},
		{"missing mtu", func() State { s := Default([]string{"a"}); s.Deployment.MTU[profile.AWG2] = 0; return s }(), "mtu"},
		{"null maps", func() State { s := Default([]string{"a"}); s.Deployment.MTU = nil; return s }(), "not null"},

		{"bot with null admins", enabledBot(func(b *Bot) { b.AdminIDs = nil }), "adminIds"},
		{"bot without a subscription port", enabledBot(func(b *Bot) { b.SubscriptionPort = 0 }), "subscriptionPort"},
		{"WDTT directory is the root", enabledBot(func(b *Bot) { b.WDTTConfigDirectory = "/" }), "root"},
		{"WDTT directory is unclean", enabledBot(func(b *Bot) { b.WDTTConfigDirectory = "/srv//relay" }), "clean absolute"},
		{"non-positive admin", enabledBot(func(b *Bot) { b.AdminIDs = []int64{0} }), "non-positive"},
		{"duplicate admin", enabledBot(func(b *Bot) { b.AdminIDs = []int64{5, 5} }), "duplicate Telegram ID"},
		{"dynamic ip without a host", enabledBot(func(b *Bot) { b.DynamicIP = true; b.PublicHost = "" }), "dynamicIp requires"},
		{"dynamic ip with an address", enabledBot(func(b *Bot) { b.DynamicIP = true; b.PublicHost = "203.0.113.7" }), "is an IP address"},
		{"enabled bot without a host", enabledBot(func(b *Bot) { b.PublicHost = "" }), "requires bot.publicHost"},
		{"enabled bot without a token", enabledBot(func(b *Bot) { b.TelegramToken = "" }), "telegramToken"},
		{"cdn host with a port", enabledBot(func(b *Bot) { b.CDNHost = "cdn.example.com:443" }), "bare host name"},
		{"ipv4 host with a trailing dot", enabledBot(func(b *Bot) { b.PublicIPv4Host = "v4.example.com." }), "bare host name"},
		{"api url with credentials", enabledBot(func(b *Bot) { b.TelegramAPIURL = "https://u:p@api.example.com" }), "http(s) URL"},
		{"api url with a query", enabledBot(func(b *Bot) { b.TelegramAPIURL = "https://api.example.com/?x=1" }), "http(s) URL"},
		{"api url over ftp", enabledBot(func(b *Bot) { b.TelegramAPIURL = "ftp://api.example.com" }), "http(s) URL"},
		{"valid api url", enabledBot(func(b *Bot) { b.TelegramAPIURL = "http://127.0.0.1:8081" }), ""},
		{"token while disabled", func() State { s := Default([]string{"a"}); s.Bot.TelegramToken = "telegram-token"; return s }(), "enabled is false"},

		{"empty reality handshake host", func() State { s := Default([]string{"a"}); s.Deployment.RealityHandshake.Host = ""; return s }(), "host is empty"},
		{"zero shadowtls handshake port", func() State { s := Default([]string{"a"}); s.Deployment.ShadowTLSHandshake.Port = 0; return s }(), "port is zero"},

		{"certificates on a tier that needs none", func() State {
			s := Default([]string{"a"})
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceFiles, Files: &CertificateFiles{CertificatePath: "/c", KeyPath: "/k"}}
			return s
		}(), "no enabled protocol needs a certificate"},
		{"domain on a tier that needs none", func() State { s := Default([]string{"a"}); s.Deployment.Domain = "vpn.example.com"; return s }(), "no enabled protocol needs a certificate"},
		{"tier B without certificates", tierB(), "certificates is required"},
		{"relative certificate paths", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceFiles, Files: &CertificateFiles{CertificatePath: "c.pem", KeyPath: "k.pem"}}
			return s
		}(), "must be absolute"},
		{"absolute certificate paths", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceFiles, Files: &CertificateFiles{CertificatePath: "/c.pem", KeyPath: "/k.pem"}}
			return s
		}(), ""},
		{"source names a branch that is absent", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceACMEHTTP, ACMEDNS: &ACMEDNS{}}
			return s
		}(), "requires the acmeHttp branch"},
		{"unknown certificate source", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: "carrier-pigeon", Files: &CertificateFiles{CertificatePath: "/c", KeyPath: "/k"}}
			return s
		}(), "unknown certificate source"},
		{"acme http without a directory", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceACMEHTTP, ACMEHTTP: &ACMEHTTP{DataDirectory: profile.ACMEDefaultDataDirectory}}
			return s
		}(), "directory/provider is empty"},
		{"acme http without a data directory", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceACMEHTTP, ACMEHTTP: &ACMEHTTP{Directory: ACMEDefaultProvider}}
			return s
		}(), "dataDirectory is empty"},
		{"acme http complete", func() State {
			s := tierB()
			s.Deployment.Certificates = &Certificates{Source: profile.CertSourceACMEHTTP, ACMEHTTP: &ACMEHTTP{
				Directory: ACMEDefaultProvider, DataDirectory: profile.ACMEDefaultDataDirectory, Email: "ops@example.com"}}
			return s
		}(), ""},
		{"cloudflare with an account branch", withACMEDNS(func(d *ACMEDNS) { d.Account = &ACMEDNSAccount{} }), "only the cloudflare branch"},
		{"cloudflare token that is a path", withACMEDNS(func(d *ACMEDNS) { d.Cloudflare.APIToken = "../token" }), "apiToken"},
		{"acmedns without an account", withACMEDNS(func(d *ACMEDNS) { d.Provider = "acmedns"; d.Cloudflare = nil }), "only the account branch"},
		{"acmedns with a bad password reference", withACMEDNS(func(d *ACMEDNS) {
			d.Provider = "acmedns"
			d.Cloudflare = nil
			d.Account = &ACMEDNSAccount{Username: "u", Password: "Bad/Name", Subdomain: "s", ServerURL: "https://acme-dns.example.com"}
		}), "password"},
		{"acmedns complete", withACMEDNS(func(d *ACMEDNS) {
			d.Provider = "acmedns"
			d.Cloudflare = nil
			d.Account = &ACMEDNSAccount{Username: "u", Password: "acme-dns-password", Subdomain: "s", ServerURL: "https://acme-dns.example.com"}
		}), ""},
		{"unknown dns provider", withACMEDNS(func(d *ACMEDNS) { d.Provider = "route53" }), "unknown DNS provider"},
		{"image without a tag", func() State { s := Default([]string{"a"}); s.Deployment.Image = "repo/core"; return s }(), "image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.state.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted; want an error containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}
