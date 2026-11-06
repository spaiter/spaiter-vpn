package cli

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// onHost fakes this machine's public addresses and what DNS says.
func onHost(t *testing.T, local []string, dns map[string]string) {
	t.Helper()
	oldLocal, oldLookup := localAddrs, lookupHost
	localAddrs = func() []netip.Addr {
		var out []netip.Addr
		for _, a := range local {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	lookupHost = func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := dns[host]; ok {
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { localAddrs, lookupHost = oldLocal, oldLookup })
}

func TestStaticAddressOffersTheDetectedIP(t *testing.T) {
	onHost(t, []string{"2001:db8::1", "203.0.113.7"}, nil)
	atTerminal(t, "\n\n") // static (the default here), no domain
	var out bytes.Buffer
	got, err := choosePublicAddress(context.Background(), newPrompt(), &out, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	// IPv4 over IPv6: VK's TURN and some clients' UDP paths have no IPv6.
	if got.host != "203.0.113.7" || got.dynamic {
		t.Fatalf("got %+v\n%s", got, out.String())
	}
}

func TestStaticAddressTakesAnOptionalDomain(t *testing.T) {
	onHost(t, []string{"203.0.113.7"}, map[string]string{"vpn.example.com": "198.51.100.1"})
	atTerminal(t, "y\nvpn.example.com\n")
	var out bytes.Buffer
	got, err := choosePublicAddress(context.Background(), newPrompt(), &out, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.host != "vpn.example.com" || got.dynamic {
		t.Fatalf("got %+v", got)
	}
	if !strings.Contains(out.String(), "not to this server") {
		t.Errorf("a domain pointing elsewhere was not flagged:\n%s", out.String())
	}
}

func TestDynamicAddressRequiresADomain(t *testing.T) {
	onHost(t, []string{"203.0.113.7"}, map[string]string{"home.example.net": "203.0.113.7"})
	// dynamic; an address literal is refused; then a domain.
	atTerminal(t, "n\n203.0.113.7\nhome.example.net\n")
	var out bytes.Buffer
	got, err := choosePublicAddress(context.Background(), newPrompt(), &out, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.host != "home.example.net" || !got.dynamic {
		t.Fatalf("got %+v", got)
	}
	for _, want := range []string{"dynamic DNS", "a dynamic one needs a domain"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Note:") {
		t.Errorf("a domain pointing here was flagged:\n%s", out.String())
	}
}

// Behind NAT the server cannot see its public address, and a home line is
// nearly always dynamic, so that is the default.
func TestBehindNATDefaultsToDynamic(t *testing.T) {
	onHost(t, nil, nil)
	atTerminal(t, "\nhome.example.net\n")
	var out bytes.Buffer
	got, err := choosePublicAddress(context.Background(), newPrompt(), &out, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.dynamic || got.host != "home.example.net" {
		t.Fatalf("got %+v", got)
	}
	if !strings.Contains(out.String(), "[y/N]") || !strings.Contains(out.String(), "does not resolve yet") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestPublicAddressFromFlags(t *testing.T) {
	onHost(t, nil, nil)
	if _, err := choosePublicAddress(context.Background(), nil, &bytes.Buffer{}, "203.0.113.7", true, false); err == nil {
		t.Fatal("-dynamic-ip with an address literal was accepted")
	}
	if _, err := choosePublicAddress(context.Background(), nil, &bytes.Buffer{}, "", true, false); err == nil {
		t.Fatal("-dynamic-ip without -public-host was accepted")
	}
	if _, err := choosePublicAddress(context.Background(), nil, &bytes.Buffer{}, "192.168.1.10", false, false); err == nil {
		t.Fatal("a private address was accepted for clients on the internet")
	}
	got, err := choosePublicAddress(context.Background(), nil, &bytes.Buffer{}, "", false, false)
	if err != nil || got.host != "" {
		t.Fatalf("without a terminal or flags the address is left empty: %+v, %v", got, err)
	}
}

func TestBootstrapStateRecordsTheAddress(t *testing.T) {
	onHost(t, nil, map[string]string{"home.example.net": "203.0.113.7"})
	path := filepath.Join(t.TempDir(), "desired.json")
	args := []string{"-users", "alice", "-o", path, "-public-host", "home.example.net", "-dynamic-ip"}
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, args); err != nil {
		t.Fatal(err)
	}
	doc := readDesired(t, path)
	if doc.Bot.PublicHost != "home.example.net" || !doc.Bot.DynamicIP {
		t.Fatalf("bot = %+v", doc.Bot)
	}
	doc.Bot.PublicHost = "203.0.113.7"
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "dynamic DNS") {
		t.Fatalf("a dynamic address held as a literal validated: %v", err)
	}
}

func TestDynamicAddressOffersTheBuiltInUpdater(t *testing.T) {
	onHost(t, nil, map[string]string{"home.example.net": "203.0.113.7"})
	// dynamic (default behind NAT), the domain, Cloudflare (default), with AAAA.
	atTerminal(t, "\nhome.example.net\n\ny\n")
	var out bytes.Buffer
	got, err := choosePublicAddress(context.Background(), newPrompt(), &out, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.ddns == nil || got.ddns.Provider != "cloudflare" || !got.ddns.IPv6 || got.ddns.Token != ddnsCredential {
		t.Fatalf("ddns = %+v", got.ddns)
	}
	if !strings.Contains(out.String(), "bootstrap credential ddns-token") {
		t.Errorf("the token's place was not named:\n%s", out.String())
	}

	// dyndns2 asks for its service and account; a plain-http URL is refused.
	atTerminal(t, "n\nhome.example.net\ndyndns2\nhttp://x\nme\ndyndns2\nhttps://dynupdate.no-ip.com/\nme\n")
	got, err = choosePublicAddress(context.Background(), newPrompt(), &bytes.Buffer{}, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.ddns == nil || got.ddns.Server != "https://dynupdate.no-ip.com" || got.ddns.Username != "me" {
		t.Fatalf("ddns = %+v", got.ddns)
	}

	// none keeps the domain and leaves updating to something else.
	atTerminal(t, "n\nhome.example.net\nnone\n")
	got, err = choosePublicAddress(context.Background(), newPrompt(), &bytes.Buffer{}, "", false, true)
	if err != nil || got.ddns != nil || got.host != "home.example.net" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestBootstrapStateDDNSFlags(t *testing.T) {
	onHost(t, nil, nil)
	path := filepath.Join(t.TempDir(), "desired.json")
	args := []string{"-users", "alice", "-o", path, "-public-host", "myvpn.duckdns.org", "-dynamic-ip", "-ddns", "duckdns"}
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, args); err != nil {
		t.Fatal(err)
	}
	if doc := readDesired(t, path); doc.DDNS == nil || doc.DDNS.Provider != "duckdns" {
		t.Fatalf("ddns = %+v", doc.DDNS)
	}
	args = []string{"-users", "alice", "-o", path, "-public-host", "vpn.example.com", "-ddns", "cloudflare"}
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, args); err == nil {
		t.Fatal("-ddns without -dynamic-ip was accepted")
	}
	args = []string{"-users", "alice", "-o", path, "-public-host", "vpn.example.com", "-dynamic-ip", "-ddns", "duckdns"}
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, args); err == nil {
		t.Fatal("duckdns for a name outside duckdns.org was accepted")
	}
}
