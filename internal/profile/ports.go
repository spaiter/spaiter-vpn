package profile

import (
	"fmt"
	"math/rand/v2"
	"sort"
)

// Random ports are drawn from below Linux's ephemeral range (32768-60999 by
// default), so a listener never collides with the source port of one of the
// host's own outgoing connections, and from above the ports common services
// claim by convention.
const (
	RandomPortMin = 10000
	RandomPortMax = 32767
)

// conventionalPorts are well-known services inside the random range. Drawing
// one would not break anything a preflight would not catch, but it would make
// the listener look like something it is not, to a scanner and to an operator.
var conventionalPorts = map[uint16]bool{
	10000: true, // Webmin
	11211: true, // memcached
	15672: true, // RabbitMQ management
	19999: true, // Netdata
	25565: true, // Minecraft
	27017: true, // MongoDB
	27018: true,
	27019: true,
}

// RandomPorts gives every protocol in protocols its own port in
// [RandomPortMin, RandomPortMax], none of them in taken.
//
// Why random at all: the defaults mirror one deployment, and a project whose
// every install listens on the same set of ports is found by scanning for that
// set. A fresh document gets ports of its own instead.
//
// Every protocol gets a distinct number even where TCP and UDP would allow
// sharing one: a port that means one thing is easier to forward, firewall and
// reason about. rnd may be nil, which uses a randomly seeded source.
func RandomPorts(rnd *rand.Rand, protocols []Protocol, taken map[uint16]bool) (map[Protocol]uint16, error) {
	span := RandomPortMax - RandomPortMin + 1
	if len(protocols)+len(taken)+len(conventionalPorts) > span/2 {
		return nil, fmt.Errorf("profile: %d ports cannot be drawn from a range of %d", len(protocols), span)
	}
	intN := rand.IntN
	if rnd != nil {
		intN = rnd.IntN
	}
	// Sorted, so a seeded source gives the same result on every run.
	ordered := append([]Protocol(nil), protocols...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	used := make(map[uint16]bool, len(taken)+len(protocols))
	for port := range taken {
		used[port] = true
	}
	ports := make(map[Protocol]uint16, len(protocols))
	for _, p := range ordered {
		if _, done := ports[p]; done {
			continue
		}
		for {
			port := uint16(RandomPortMin + intN(span))
			if !used[port] && !conventionalPorts[port] {
				used[port] = true
				ports[p] = port
				break
			}
		}
	}
	return ports, nil
}
