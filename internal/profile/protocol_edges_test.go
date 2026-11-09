package profile

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestProtocolAddressingAndExposureFollowTheSpec(t *testing.T) {
	spec := Defaults([]string{"alice"})
	spec.PublicListen = netip.MustParseAddr("0.0.0.0")
	spec.ShadowsocksListen = netip.MustParseAddr("127.0.0.1")
	spec.CDNListen = netip.MustParseAddr("127.0.0.1")

	if Shadowsocks.ListenAddress(spec) != spec.ShadowsocksListen || VLESSWSCDN.ListenAddress(spec) != spec.CDNListen || TUIC.ListenAddress(spec) != spec.PublicListen {
		t.Error("ListenAddress")
	}
	for _, p := range []Protocol{Shadowsocks, VLESSWSCDN, WGMasque, WGWDTT} {
		if p.IsInternetFacing(spec) {
			t.Errorf("%s must not be opened in the firewall", p)
		}
	}
	for _, p := range []Protocol{TUIC, Hysteria2, VLESSReality} {
		if !p.IsInternetFacing(spec) {
			t.Errorf("%s must be opened in the firewall", p)
		}
	}
	// An unset listen address is not a public door either.
	if TUIC.IsInternetFacing(Spec{}) {
		t.Error("an unset address counted as internet-facing")
	}

	for p, want := range map[Protocol]string{AWG2: "udp", AWG3: "udp", WGMasque: "udp", WGWDTT: "udp", Hysteria2: "udp", TUIC: "udp", MASQUEWG: "udp", Shadowsocks: "tcp,udp", VLESSReality: "tcp"} {
		if got := strings.Join(p.Networks(), ","); got != want {
			t.Errorf("%s networks = %q, want %q", p, got, want)
		}
	}
}

func TestProtocolsAreSortedForDeterministicGeneration(t *testing.T) {
	in := []Protocol{TUIC, AWG2, Hysteria2}
	got := sortedProtocols(in)
	if got[0] != AWG2 || in[0] != TUIC {
		t.Errorf("sorted = %v, input mutated = %v", got, in)
	}
}

func TestSubnetMovesRefuseWhatCannotBePreserved(t *testing.T) {
	from, to := netip.MustParsePrefix("10.10.0.0/24"), netip.MustParsePrefix("10.20.0.0/24")
	moved, err := ReassignAddressPreserveHost(netip.MustParseAddr("10.10.0.7"), from, to)
	if err != nil || moved.String() != "10.20.0.7" {
		t.Errorf("moved = %v, %v", moved, err)
	}
	for name, c := range map[string]struct {
		addr     string
		from, to netip.Prefix
		want     string
	}{
		"ipv6 prefixes":   {"10.10.0.7", netip.MustParsePrefix("fd00::/64"), to, "valid IPv4 prefixes"},
		"unmasked source": {"10.10.0.7", netip.MustParsePrefix("10.10.0.1/24"), to, "network prefixes"},
		"outside source":  {"10.99.0.7", from, to, "outside source subnet"},
		"does not fit":    {"10.10.0.200", from, netip.MustParsePrefix("10.20.0.0/26"), "does not fit"},
	} {
		if _, err := ReassignAddressPreserveHost(netip.MustParseAddr(c.addr), c.from, c.to); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if _, err := ReassignAddressPreserveHost(netip.Addr{}, from, to); err == nil {
		t.Error("an invalid address was moved")
	}
}

func TestSmallGeneratorHelpers(t *testing.T) {
	for method, want := range map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32, "2022-blake3-chacha20-poly1305": 32, "aes-256-gcm": 32} {
		if got, err := shadowsocksKeyLength(method); err != nil || got != want {
			t.Errorf("%s = %d, %v", method, got, err)
		}
	}
	if _, err := shadowsocksKeyLength("2022-blake3-future"); err == nil {
		t.Error("an unknown 2022 method was guessed")
	}
	if pathSuffix("abcdefghijkl") != "abcdefgh" || pathSuffix("abc") != "abc" {
		t.Error("pathSuffix")
	}
	prefix := netip.MustParsePrefix("10.0.0.0/30")
	if got, err := hostInPrefix(prefix, 2); err != nil || got.String() != "10.0.0.2/30" {
		t.Errorf("host 2 = %v, %v", got, err)
	}
	if _, err := hostInPrefix(prefix, 9); err == nil {
		t.Error("a host beyond the prefix was returned")
	}
	if _, err := hostInPrefix(netip.MustParsePrefix("255.255.255.252/30"), 9); err == nil {
		t.Error("ran off the end without an error")
	}
}

func TestCredentialSlotsJoinTheTwoPartTUICCredential(t *testing.T) {
	slots := UserSecrets{TUICUUID: "u", TUICPassword: "p"}.CredentialSlots()
	if slots[SlotTUIC] != "u\x00p" {
		t.Errorf("tuic slot = %q", slots[SlotTUIC])
	}
	if (UserSecrets{}).CredentialSlots()[SlotTUIC] != "" {
		t.Error("an empty user holds a TUIC credential")
	}
}

func TestRenderRefusesAnInvalidSpecAndSerialisesBothHalves(t *testing.T) {
	if _, err := Render(context.Background(), Spec{}); err == nil {
		t.Error("an empty spec was rendered")
	}
	spec := Defaults([]string{"alice"})
	spec.XDPInterfaces = []string{"eth0"}
	rendered, err := Render(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(rendered.ConfigJSON) == 0 || !strings.HasSuffix(string(rendered.SecretsJSON), "}\n") {
		t.Error("an empty half")
	}
}
