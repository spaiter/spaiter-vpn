package provision

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNextIPSkipsWhatIsTaken(t *testing.T) {
	cases := []struct {
		name   string
		subnet string
		used   []string
		want   string
	}{
		{"an empty subnet starts after the server", "10.10.0.1/24", nil, "10.10.0.2"},
		{"a gap is reused", "10.10.0.1/24",
			[]string{"10.10.0.2/32", "10.10.0.4/32"}, "10.10.0.3"},
		{"a bare address counts too", "10.10.0.1/24",
			[]string{"10.10.0.2"}, "10.10.0.3"},
		{"several per peer", "10.10.0.1/24",
			[]string{"10.10.0.2/32", "10.10.0.3/32", "10.10.0.4/32"}, "10.10.0.5"},
		{"a smaller subnet", "192.168.9.1/29",
			[]string{"192.168.9.2/32"}, "192.168.9.3"},
		{"IPv6", "fd00::1/64", []string{"fd00::2/128"}, "fd00::3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NextIP(c.subnet, c.used)
			if err != nil {
				t.Fatalf("NextIP: %v", err)
			}
			if got != c.want {
				t.Errorf("NextIP(%s, %v) = %s, want %s", c.subnet, c.used, got, c.want)
			}
		})
	}
}

// TestNextIPNeverHandsOutTheServersAddress: the endpoint answers on it, and a
// client configured with it would send its own traffic to itself.
func TestNextIPNeverHandsOutTheServersAddress(t *testing.T) {
	for _, subnet := range []string{"10.10.0.1/24", "10.10.0.5/24"} {
		got, err := NextIP(subnet, nil)
		if err != nil {
			t.Fatalf("NextIP(%s): %v", subnet, err)
		}
		if got == "10.10.0.1" || strings.HasPrefix(subnet, got+"/") {
			t.Errorf("NextIP(%s) = %s, which the server holds", subnet, got)
		}
		if got == "10.10.0.0" {
			t.Errorf("NextIP(%s) returned the network address", subnet)
		}
	}
}

// TestNextIPRefusesWhatItCannotRead is the conservative half: an entry that
// does not parse may well be the peer already holding the address this would
// return, and skipping it hands the same address to two tunnels.
func TestNextIPRefusesWhatItCannotRead(t *testing.T) {
	_, err := NextIP("10.10.0.1/24", []string{"10.10.0.2/32", "not-an-address"})
	if err == nil {
		t.Fatal("an unreadable peer address was skipped rather than refused")
	}
	if !strings.Contains(err.Error(), "not-an-address") {
		t.Errorf("error should name the entry: %v", err)
	}
}

func TestNextIPReportsAFullSubnet(t *testing.T) {
	// A /30 holds .0 network, .1 server, .2 usable, .3 broadcast.
	_, err := NextIP("10.9.0.1/30", []string{"10.9.0.2/32"})
	if err == nil {
		t.Fatal("a full subnet produced an address")
	}
	if !strings.Contains(err.Error(), "no free address") {
		t.Errorf("error = %v", err)
	}
}

func TestNextIPRejectsAnUnreadableSubnet(t *testing.T) {
	for _, subnet := range []string{"", "10.10.0.1", "garbage/24"} {
		if _, err := NextIP(subnet, nil); err == nil {
			t.Errorf("NextIP(%q) was accepted", subnet)
		}
	}
}

// TestAddrListAcceptsBothForms: this deployment writes allowed_ips as one
// string per peer, while the core's schema and the installer use a list. A
// reader that handles only one form sees no addresses in the other and goes on
// to hand out an address already in use.
func TestAddrListAcceptsBothForms(t *testing.T) {
	cases := map[string][]string{
		`"10.10.0.2/32"`:                 {"10.10.0.2/32"},
		`["10.10.0.2/32"]`:               {"10.10.0.2/32"},
		`["10.10.0.2/32","fd00::2/128"]`: {"10.10.0.2/32", "fd00::2/128"},
		`""`:                             nil,
		`null`:                           nil,
		`[]`:                             {},
	}
	for input, want := range cases {
		var got AddrList
		if err := json.Unmarshal([]byte(input), &got); err != nil {
			t.Errorf("unmarshal %s: %v", input, err)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("%s -> %v, want %v", input, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s -> %v, want %v", input, got, want)
				break
			}
		}
	}
}

func TestAddrListRejectsSomethingElse(t *testing.T) {
	var got AddrList
	if err := json.Unmarshal([]byte(`{"ip":"10.10.0.2"}`), &got); err == nil {
		t.Fatal("an object was accepted as allowed_ips")
	}
}
