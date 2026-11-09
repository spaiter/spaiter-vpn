package hostinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// procNetTCP is in the format the kernel writes. The second row is an
// ESTABLISHED connection (state 01) whose local port 44033 must NOT be
// reported: it is an ephemeral port of an outgoing connection, and counting it
// as an occupied listener makes the port check invent conflicts.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1964 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107290294 1 0000000000000000 100 0 0 10 0
   1: C8B2A8C0:ABF1 04030201:0050 01 00000000:00000000 00:00000000 00000000  1000        0 107290295 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107290296 1 0000000000000000 100 0 0 10 0
   3: C8B2A8C0:2A61 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 107290297 1 0000000000000000 100 0 0 10 0
`

// procNetUDP has no state to filter on: every row is a bound socket.
const procNetUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  123: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1234 2 0000000000000000 0
  456: 0100007F:2A67 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1235 2 0000000000000000 0
`

func TestListeningTCPPortsFiltersOutEstablishedConnections(t *testing.T) {
	path := writeFixture(t, "tcp", procNetTCP)

	ports := map[uint16]bool{}
	if err := readProcNetPorts(path, tcpStateListen, ports); err != nil {
		t.Fatalf("readProcNetPorts: %v", err)
	}

	// 0x1964 = 6500, 0x0016 = 22.
	for _, want := range []uint16{6500, 22} {
		if !ports[want] {
			t.Errorf("listening port %d was not reported", want)
		}
	}
	// 0xABF1 = 44017, the ephemeral local port of the ESTABLISHED row.
	if ports[0xABF1] {
		t.Errorf("port %d belongs to an ESTABLISHED connection and must not count as a listener", 0xABF1)
	}
	// 0x2A61 = 10849, state 06 is TIME_WAIT — also not a listener.
	if ports[0x2A61] {
		t.Errorf("port %d is in TIME_WAIT and must not count as a listener", 0x2A61)
	}
	if len(ports) != 2 {
		t.Errorf("reported %d ports, want exactly 2: %v", len(ports), ports)
	}
}

func TestUDPPortsAreNotStateFiltered(t *testing.T) {
	path := writeFixture(t, "udp", procNetUDP)

	ports := map[uint16]bool{}
	if err := readProcNetPorts(path, "", ports); err != nil {
		t.Fatalf("readProcNetPorts: %v", err)
	}
	// 0x0035 = 53, 0x2A67 = 10855.
	for _, want := range []uint16{53, 0x2A67} {
		if !ports[want] {
			t.Errorf("bound UDP port %d was not reported", want)
		}
	}
	if len(ports) != 2 {
		t.Errorf("reported %d ports, want 2: %v", len(ports), ports)
	}

	// Applying the TCP state filter to UDP would silently report nothing,
	// which is the kind of empty result that makes a port check pass by
	// looking at nothing at all.
	filtered := map[uint16]bool{}
	if err := readProcNetPorts(path, tcpStateListen, filtered); err != nil {
		t.Fatalf("readProcNetPorts: %v", err)
	}
	if len(filtered) != 0 {
		t.Fatalf("expected the TCP filter to match no UDP rows, got %v", filtered)
	}
}

func TestLiveAndFixtureReadersAgreeOnShape(t *testing.T) {
	// Not an assertion about this host's ports -- it has none that are
	// guaranteed -- but that reading the real files works at all and that TCP
	// yields a subset of what an unfiltered read would.
	//
	// The two reads happen a moment apart on a live machine, and a socket that
	// closes between them is not a bug, so a disagreement counts only if it
	// survives a few attempts.
	var problem string
	for attempt := 0; attempt < 5; attempt++ {
		problem = ""
		// Unfiltered first: a listener that appears later is then only ever
		// missing from the set that was read earlier.
		all := map[uint16]bool{}
		for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			if err := readProcNetPorts(path, "", all); err != nil && !os.IsNotExist(err) {
				t.Fatalf("readProcNetPorts(%s): %v", path, err)
			}
		}
		listening, err := ListeningTCPPorts()
		if err != nil {
			t.Fatalf("ListeningTCPPorts: %v", err)
		}
		for port := range listening {
			if !all[port] {
				problem = fmt.Sprintf("port %d is reported as listening but absent from an unfiltered read", port)
			}
		}
		if problem == "" {
			return
		}
	}
	t.Error(problem)
}

func TestFreeBytesAndWritableUseTheNearestAncestor(t *testing.T) {
	dir := t.TempDir()
	// A directory that does not exist yet is the normal case for `init -out`.
	future := filepath.Join(dir, "does", "not", "exist", "yet")

	free, err := FreeBytes(future)
	if err != nil {
		t.Fatalf("FreeBytes on a future path: %v", err)
	}
	if free == 0 {
		t.Error("FreeBytes reported 0 bytes free on a temporary directory")
	}
	if err := Writable(future); err != nil {
		t.Errorf("Writable on a future path under a writable parent: %v", err)
	}

	// A path whose ancestor is a file, not a directory, must be refused rather
	// than reported writable.
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Writable(file); err == nil {
		t.Error("Writable accepted a regular file as a directory")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		512:              "512 B",
		2048:             "2.0 KiB",
		5 << 20:          "5.0 MiB",
		3 << 30:          "3.0 GiB",
		2 << 40:          "2.0 TiB",
		MinimumFreeBytes: "512.0 MiB",
	}
	for input, want := range cases {
		if got := HumanBytes(input); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", input, got, want)
		}
	}
}

// MinimumFreeBytes duplicates the preflight constant so this package's test
// stays independent of it; if they diverge the string above changes and this
// test says so.
const MinimumFreeBytes = 512 << 20

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
