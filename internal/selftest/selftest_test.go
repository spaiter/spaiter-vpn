package selftest

import (
	"net/netip"
	"testing"
)

func TestChooseTestSubnetKeepsDefaultOrMovesDeterministically(t *testing.T) {
	preferred := netip.MustParsePrefix("10.99.0.0/24")
	free := &LiveConfig{EndpointAddresses: []string{"10.10.0.1/24"}}
	got, err := chooseTestSubnet(free, preferred)
	if err != nil || got != preferred {
		t.Fatalf("free preferred subnet = %s, %v", got, err)
	}

	colliding := &LiveConfig{EndpointAddresses: []string{"10.99.0.1/24", "10.98.0.1/24"}}
	got, err = chooseTestSubnet(colliding, preferred)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParsePrefix("10.97.0.0/24"); got != want {
		t.Fatalf("fallback subnet = %s, want %s", got, want)
	}
}
