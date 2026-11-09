package hostinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// tcpStateListen is the st column of /proc/net/tcp for a listening socket.
const tcpStateListen = "0A"

// ListeningUDPPorts returns every local port with a UDP socket bound, across
// both IPv4 and IPv6.
//
// Read from /proc rather than probed by binding: binding to a port to see
// whether it is free would steal it from the service under test, and probing
// by sending a datagram proves nothing because UDP has no accept.
//
// Unlike TCP there is no state to filter on: every row in /proc/net/udp is a
// bound socket.
func ListeningUDPPorts() (map[uint16]bool, error) {
	return readPorts([]string{"/proc/net/udp", "/proc/net/udp6"}, "")
}

// ListeningTCPPorts returns every local port with a socket in LISTEN.
//
// The state filter is essential: /proc/net/tcp also lists every established
// connection, whose ephemeral local port would otherwise look like an occupied
// listener and make the port check report conflicts that do not exist.
func ListeningTCPPorts() (map[uint16]bool, error) {
	return readPorts([]string{"/proc/net/tcp", "/proc/net/tcp6"}, tcpStateListen)
}

func readPorts(paths []string, requireState string) (map[uint16]bool, error) {
	ports := map[uint16]bool{}
	for _, path := range paths {
		if err := readProcNetPorts(path, requireState, ports); err != nil {
			// The v6 files are absent on an IPv4-only kernel; not an error.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
	}
	return ports, nil
}

func readProcNetPorts(path, requireState string, into map[uint16]bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return fmt.Errorf("%s is empty", path)
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if requireState != "" && fields[3] != requireState {
			continue
		}
		// local_address is "hexaddr:hexport".
		_, portHex, found := strings.Cut(fields[1], ":")
		if !found {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		into[uint16(port)] = true
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}
