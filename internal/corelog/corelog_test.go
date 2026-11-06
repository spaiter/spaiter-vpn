package corelog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realLog is taken from a live core log, its addresses and IDs replaced
// after the 2026-10-22 run, so the parser is tested against the format the fork
// actually writes rather than one reconstructed from its source.
//
// It deliberately includes the two decoys that make naive matching useless:
// the `sniff(bittorrent,100ms)` lines, which are the sniff RULE firing on every
// connection and not detections at all, and a detection on a different inbound.
const realLog = `+0000 2026-10-22 22:09:08 DEBUG router: match[0] => sniff(bittorrent,100ms)
+0000 2026-10-22 22:09:08 DEBUG router: match[0] => sniff(bittorrent,100ms)
+0000 2026-10-22 22:09:10 INFO router: bittorrent sniff detection: network=udp, detector=dht, inbound=bt-test-in, source=10.99.0.2:40844, destination=192.0.2.1:6881, payload_bytes=92
+0000 2026-10-22 22:09:10 DEBUG router: match[1] protocol=bittorrent => reject(drop,xdp-block)
+0000 2026-10-22 22:09:10 DEBUG router: connection closed: rejected
+0000 2026-10-22 22:09:12 INFO router: bittorrent sniff detection: network=udp, detector=udp-tracker-connect, inbound=bt-test-in, source=10.99.0.2:47371, destination=192.0.2.1:6969, payload_bytes=16
+0000 2026-10-22 22:09:12 DEBUG router: match[1] protocol=bittorrent => reject(drop,xdp-block)
+0000 2026-10-22 22:09:13 INFO router: bittorrent sniff detection: network=udp, detector=lsd-bt-search, inbound=bt-test-in, source=10.99.0.2:51000, destination=192.0.2.1:6771, payload_bytes=118
+0000 2026-10-22 22:09:13 DEBUG router: XDP: skipping local peer endpoint 127.0.0.1 for 10.99.0.2
+0000 2026-10-22 22:09:14 INFO router: bittorrent sniff detection: network=tcp, detector=handshake, inbound=awg-in, source=10.10.0.5:12345, destination=203.0.113.9:51413, payload_bytes=68
`

func TestDetectionsIgnoreTheSniffRuleLines(t *testing.T) {
	slice := &LogSlice{Text: realLog}

	// The whole slice mentions "bittorrent" nine times; only four of those are
	// detections. A counter that trusted the word would report a pass on a
	// server that detects nothing.
	if got := strings.Count(realLog, "bittorrent"); got < 8 {
		t.Fatalf("fixture lost its decoy lines: only %d mentions of bittorrent", got)
	}

	detections := slice.Detections()
	if len(detections) != 4 {
		t.Fatalf("parsed %d detections, want 4:\n%+v", len(detections), detections)
	}

	first := detections[0]
	if first.Network != "udp" || first.Detector != "dht" || first.Inbound != "bt-test-in" {
		t.Errorf("first detection parsed wrong: %+v", first)
	}
	if first.Destination != "192.0.2.1:6881" || first.DestinationPort != 6881 {
		t.Errorf("destination parsed wrong: %q / %d", first.Destination, first.DestinationPort)
	}
	if first.Source != "10.99.0.2:40844" {
		t.Errorf("source parsed wrong: %q", first.Source)
	}
	if first.PayloadBytes != 92 {
		t.Errorf("payload_bytes parsed as %d, want 92", first.PayloadBytes)
	}

	// The last one is on a different inbound, which is how a real client's
	// traffic landing in the same window must look so the caller can exclude it.
	if last := detections[3]; last.Inbound != "awg-in" || last.Network != "tcp" {
		t.Errorf("detection from another inbound parsed wrong: %+v", last)
	}
}

func TestRejectionsParseTheMethodWithoutPinningTheRuleIndex(t *testing.T) {
	slice := &LogSlice{Text: realLog}
	rejections := slice.Rejections()
	if len(rejections) != 2 {
		t.Fatalf("parsed %d rejections, want 2: %v", len(rejections), rejections)
	}
	for _, r := range rejections {
		if r != "drop,xdp-block" {
			t.Errorf("rejection method parsed as %q, want %q", r, "drop,xdp-block")
		}
	}

	// The rule index must not be part of the match: it depends on how many
	// rules precede the reject rule, and a generated config could legitimately
	// place it elsewhere.
	reindexed := strings.ReplaceAll(realLog, "match[1]", "match[7]")
	if got := len(((&LogSlice{Text: reindexed}).Rejections())); got != 2 {
		t.Errorf("parsed %d rejections after renumbering the rule, want 2", got)
	}
}

func TestLogSliceDetectsNothingInAnEmptyWindow(t *testing.T) {
	// The negative assertions in the self-test are over this list, so it has
	// to be genuinely empty rather than accidentally so — an empty list makes
	// "nothing was falsely detected" vacuously true, which is why the control
	// probe exists.
	slice := &LogSlice{Text: ""}
	if got := slice.Detections(); len(got) != 0 {
		t.Fatalf("empty log yielded %d detections", len(got))
	}
	if slice.Lines() != 0 {
		t.Fatalf("empty log reported %d lines", slice.Lines())
	}
}

func TestReadSinceReturnsOnlyTheNewTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.log")

	before := "old line that must not appear in the result\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	offset, err := Offset(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset != int64(len(before)) {
		t.Fatalf("offset is %d, want %d", offset, len(before))
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(realLog); err != nil {
		t.Fatal(err)
	}
	file.Close()

	slice, err := ReadSince(path, offset)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if strings.Contains(slice.Text, "old line") {
		t.Error("the slice includes a line written before the offset was taken")
	}
	if len(slice.Detections()) != 4 {
		t.Errorf("the slice has %d detections, want 4", len(slice.Detections()))
	}
}

func TestReadSinceRefusesARotatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.log")
	if err := os.WriteFile(path, []byte(realLog), 0o600); err != nil {
		t.Fatal(err)
	}
	offset, err := Offset(path)
	if err != nil {
		t.Fatal(err)
	}

	// Rotation mid-run makes the offset meaningless. Reading from it anyway
	// would silently produce a window starting in the wrong place, which is
	// worse than no answer.
	if err := os.WriteFile(path, []byte("truncated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSince(path, offset); err == nil {
		t.Fatal("ReadSince accepted a file that shrank; a rotated log must be reported, not parsed")
	}
}

func TestReadSinceHandlesLongDetectionLines(t *testing.T) {
	// Real detection lines carry a hex dump of the payload, so they run to
	// several kilobytes. A default bufio.Scanner would stop at 64 KiB and
	// silently drop the rest of the window.
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.log")
	long := strings.Repeat("x", 300*1024)
	content := "bittorrent sniff detection: network=udp, detector=dht, inbound=t, source=1.2.3.4:1, destination=5.6.7.8:6881, payload_bytes=1 " + long + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	slice, err := ReadSince(path, 0)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if len(slice.Detections()) != 1 {
		t.Fatalf("a %d-byte line yielded %d detections, want 1", len(content), len(slice.Detections()))
	}
}

func TestPortOf(t *testing.T) {
	cases := map[string]uint16{
		"192.0.2.1:6881":   6881,
		"[2001:db8::1]:80": 80,
		"no-port":          0,
		"host:notaport":    0,
	}
	for input, want := range cases {
		if got := portOf(input); got != want {
			t.Errorf("portOf(%q) = %d, want %d", input, got, want)
		}
	}
}

// TestSummariseSeparatesDetectionsFromTheSniffRule is the property the `logs`
// command rests on. Against the live deployment this turned 234,558 lines into
// 8 detections — a `grep bittorrent` would have returned tens of thousands,
// because the sniff RULE logs a line per connection.
func TestSummariseSeparatesDetectionsFromTheSniffRule(t *testing.T) {
	s := (&LogSlice{Text: realLog}).Summarise()

	if s.Detections != 4 {
		t.Fatalf("summarised %d detections, want 4", s.Detections)
	}
	if s.ByDetector["dht"] != 1 || s.ByDetector["udp-tracker-connect"] != 1 || s.ByDetector["lsd-bt-search"] != 1 {
		t.Errorf("detector counts are wrong: %v", s.ByDetector)
	}
	if s.ByDetector["handshake"] != 1 {
		t.Errorf("the detection on another inbound was dropped: %v", s.ByDetector)
	}
	if s.ByInbound["bt-test-in"] != 3 || s.ByInbound["awg-in"] != 1 {
		t.Errorf("inbound attribution is wrong: %v", s.ByInbound)
	}

	// The ephemeral port must not make every event a different client.
	if s.BySource["10.99.0.2"] != 3 {
		t.Errorf("source aggregation kept the ports: %v", s.BySource)
	}

	if s.Rejections["drop,xdp-block"] != 2 {
		t.Errorf("rejection counts are wrong: %v", s.Rejections)
	}
	if s.LocalPeerSkips != 1 {
		t.Errorf("loopback skips counted as %d, want 1", s.LocalPeerSkips)
	}
	if s.XDPBlocks != 0 {
		t.Errorf("counted %d enforced bans in a fixture that has none", s.XDPBlocks)
	}
}

// TestSummariseCountsEnforcedBansSeparately keeps apart the two outcomes that
// look alike in the log and are not: a dropped connection and a banned client.
func TestSummariseCountsEnforcedBansSeparately(t *testing.T) {
	// Taken from the live log, where a real user on the AmneziaWG 3.1 endpoint
	// was detected and then actually banned.
	const withBan = realLog +
		"+0000 2026-10-23 09:14:02 INFO router: bittorrent sniff detection: network=udp, detector=dht, inbound=awg3-in, source=10.40.0.8:6881, destination=203.0.113.94:6881, payload_bytes=104\n" +
		"+0000 2026-10-23 09:14:02 INFO xdp: XDP blocked 203.0.113.66 user=100000006\n"

	s := (&LogSlice{Text: withBan}).Summarise()
	if s.XDPBlocks != 1 {
		t.Errorf("enforced bans counted as %d, want 1", s.XDPBlocks)
	}
	if s.Detections != 5 {
		t.Errorf("detections counted as %d, want 5", s.Detections)
	}
	if s.ByInbound["awg3-in"] != 1 {
		t.Errorf("the real client's inbound was not attributed: %v", s.ByInbound)
	}
}

func TestSummariseOfAnEmptyLogClaimsNothing(t *testing.T) {
	s := (&LogSlice{Text: ""}).Summarise()
	if s.Detections != 0 || s.XDPBlocks != 0 || len(s.ByDetector) != 0 {
		t.Fatalf("an empty log produced findings: %+v", s)
	}
}
