// Package hostinfo reads the few facts about the host that the generator
// cannot reasonably ask the operator for.
package hostinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultRouteInterface returns the interface carrying the IPv4 default route,
// which is where the XDP blocker has to attach: a program bound to the wrong
// interface loads successfully and then sees no traffic, so guessing "eth0"
// would produce a deployment that looks fine and bans nobody.
func DefaultRouteInterface() (string, error) {
	return defaultRouteInterface("/proc/net/route")
}

func defaultRouteInterface(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", fmt.Errorf("%s is empty", path)
	}

	// Pick the default route with the lowest metric rather than the first one
	// listed: a host with several uplinks lists them all, and the kernel uses
	// the cheapest.
	best := ""
	bestMetric := -1
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 {
			continue
		}
		// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		// Destination 00000000 is the default route.
		if fields[1] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if best == "" {
		return "", fmt.Errorf("no IPv4 default route in %s", path)
	}
	return best, nil
}
