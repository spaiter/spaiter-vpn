package profile

import (
	"math/rand/v2"
	"testing"
)

func TestRandomPortsAreDistinctInRangeAndAvoidTaken(t *testing.T) {
	protocols := make([]Protocol, 0, len(DefaultPorts()))
	for p := range DefaultPorts() {
		protocols = append(protocols, p)
	}
	taken := map[uint16]bool{20000: true, 20001: true}
	for seed := uint64(0); seed < 200; seed++ {
		ports, err := RandomPorts(rand.New(rand.NewPCG(seed, seed)), protocols, taken)
		if err != nil {
			t.Fatal(err)
		}
		if len(ports) != len(protocols) {
			t.Fatalf("seed %d: %d ports for %d protocols", seed, len(ports), len(protocols))
		}
		seen := map[uint16]Protocol{}
		for p, port := range ports {
			if port < RandomPortMin || port > RandomPortMax {
				t.Fatalf("seed %d: %s got %d, outside the random range", seed, p, port)
			}
			if taken[port] || conventionalPorts[port] {
				t.Fatalf("seed %d: %s got %d, which was excluded", seed, p, port)
			}
			if other, dup := seen[port]; dup {
				t.Fatalf("seed %d: %s and %s share %d", seed, p, other, port)
			}
			seen[port] = p
		}
	}
}

// The point of drawing at all: a fresh document must not carry the set of
// ports the original deployment listens on.
func TestRandomPortsDoNotReproduceTheDefaults(t *testing.T) {
	defaults := DefaultPorts()
	protocols := make([]Protocol, 0, len(defaults))
	for p := range defaults {
		protocols = append(protocols, p)
	}
	ports, err := RandomPorts(nil, protocols, nil)
	if err != nil {
		t.Fatal(err)
	}
	same := 0
	for p, port := range ports {
		if defaults[p] == port {
			same++
		}
	}
	if same == len(defaults) {
		t.Fatal("random ports reproduced the default set")
	}
}

func TestRandomPortsIsDeterministicForASeed(t *testing.T) {
	protocols := []Protocol{VLESSReality, AWG2, Hysteria2}
	a, _ := RandomPorts(rand.New(rand.NewPCG(1, 2)), protocols, nil)
	b, _ := RandomPorts(rand.New(rand.NewPCG(1, 2)), []Protocol{Hysteria2, AWG2, VLESSReality}, nil)
	for _, p := range protocols {
		if a[p] != b[p] {
			t.Fatalf("%s: %d vs %d for the same seed", p, a[p], b[p])
		}
	}
}
