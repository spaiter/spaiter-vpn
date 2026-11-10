package sniff_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Corpus-driven tests for the BitTorrent sniffers, migrated from the
// standalone spaiter/BitTorrentBlocker project so the detection logic that
// actually runs in production is the logic under test. The library version was
// a separate NFQUEUE tool; this fork's sniffers are what the route rule
// {"action":"sniff","sniffer":"bittorrent"} invokes.
//
// The sniffer lists below are copied from route/rule/rule_action.go, where
// sniffer name "bittorrent" is expanded. Keep them in sync: if a sniffer is
// added there and not here, the corpus silently stops covering it.
//
// Provenance and licensing of every capture: testdata/pcap/NOTICE.md.

func btStreamSniffers() []sniff.StreamSniffer {
	return []sniff.StreamSniffer{
		sniff.BitTorrent,
		sniff.BitTorrentMessage,
		sniff.BitTorrentFAST,
		sniff.BitTorrentExtended,
		sniff.BitTorrentHTTP,
		sniff.BitTorrentSignature,
	}
}

func btPacketSniffers() []sniff.PacketSniffer {
	return []sniff.PacketSniffer{
		sniff.UTP,
		sniff.UDPTracker,
		sniff.BitTorrentDHTPacket,
		sniff.BitTorrentLSD,
		sniff.BitTorrentSignaturePacket,
	}
}

// ---------------------------------------------------------------- pcap reader

type capturedPacket struct {
	isUDP   bool
	payload []byte
	dest    M.Socksaddr
}

// readCapture parses a classic pcap or pcapng file into transport payloads.
//
// Written by hand rather than pulled in as a dependency: this fork is a VPN
// core and adding gopacket to the main module for a test would drag a large
// dependency tree into every build.
//
// It returns an error rather than calling t.Skip or t.Fatal, deliberately. The
// first version skipped, and because testing.T.Skip aborts the whole test, a
// single malformed capture in the corpus (fuzz-2021-10-13.pcap, which nDPI
// also documents as unreadable) silently cancelled the entire false-positive
// sweep. The test reported PASS while checking nothing.
func readCapture(path string) ([]capturedPacket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var frames [][]byte
	switch {
	case len(data) > 4 && (data[0] == 0xD4 || data[0] == 0xA1):
		// Classic pcap. The bytes on disk are the magic as the capturing host
		// wrote it, so d4c3b2a1 means little-endian.
		little := data[0] == 0xD4
		get32 := func(b []byte) uint32 {
			if little {
				return binary.LittleEndian.Uint32(b)
			}
			return binary.BigEndian.Uint32(b)
		}
		for off := 24; off+16 <= len(data); {
			incl := int(get32(data[off+8 : off+12]))
			if incl <= 0 || incl > 262144 || off+16+incl > len(data) {
				break
			}
			frames = append(frames, data[off+16:off+16+incl])
			off += 16 + incl
		}
	case len(data) > 4 && binary.LittleEndian.Uint32(data[:4]) == 0x0A0D0D0A:
		// pcapng: only Enhanced Packet Blocks carry payloads.
		for off := 0; off+12 <= len(data); {
			blockType := binary.LittleEndian.Uint32(data[off : off+4])
			blockLen := int(binary.LittleEndian.Uint32(data[off+4 : off+8]))
			if blockLen < 12 || off+blockLen > len(data) {
				break
			}
			if blockType == 6 && off+28 <= len(data) {
				capLen := int(binary.LittleEndian.Uint32(data[off+20 : off+24]))
				if capLen > 0 && off+28+capLen <= len(data) {
					frames = append(frames, data[off+28:off+28+capLen])
				}
			}
			off += blockLen
		}
	default:
		return nil, fmt.Errorf("unrecognised capture format")
	}

	var out []capturedPacket
	for _, frame := range frames {
		pkt, ok := decodeFrame(frame)
		if ok {
			out = append(out, pkt)
		}
	}
	return out, nil
}

func decodeFrame(frame []byte) (capturedPacket, bool) {
	if len(frame) < 14 {
		return capturedPacket{}, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	rest := frame[14:]

	var (
		proto   byte
		dstAddr netip.Addr
		tr      []byte
	)
	switch etherType {
	case 0x0800:
		if len(rest) < 20 {
			return capturedPacket{}, false
		}
		proto = rest[9]
		dstAddr = netip.AddrFrom4([4]byte(rest[16:20]))
		ihl := int(rest[0]&0x0F) * 4
		if ihl < 20 || ihl > len(rest) {
			return capturedPacket{}, false
		}
		tr = rest[ihl:]
	case 0x86DD:
		if len(rest) < 40 {
			return capturedPacket{}, false
		}
		proto = rest[6]
		dstAddr = netip.AddrFrom16([16]byte(rest[24:40]))
		tr = rest[40:]
	default:
		return capturedPacket{}, false
	}

	switch proto {
	case 6:
		if len(tr) < 20 {
			return capturedPacket{}, false
		}
		dataOff := int(tr[12]>>4) * 4
		if dataOff < 20 || dataOff > len(tr) {
			return capturedPacket{}, false
		}
		payload := tr[dataOff:]
		if len(payload) == 0 {
			return capturedPacket{}, false
		}
		return capturedPacket{
			payload: payload,
			dest:    M.SocksaddrFrom(dstAddr, binary.BigEndian.Uint16(tr[2:4])),
		}, true
	case 17:
		if len(tr) < 8 {
			return capturedPacket{}, false
		}
		payload := tr[8:]
		if len(payload) == 0 {
			return capturedPacket{}, false
		}
		return capturedPacket{
			isUDP:   true,
			payload: payload,
			dest:    M.SocksaddrFrom(dstAddr, binary.BigEndian.Uint16(tr[2:4])),
		}, true
	}
	return capturedPacket{}, false
}

// ------------------------------------------------------------------- sniffing

// sniffOne runs the production sniffer set over a single payload and reports
// whether any of them claimed it as BitTorrent, plus which detector fired.
func sniffOne(pkt capturedPacket) (bool, string) {
	metadata := &adapter.InboundContext{Destination: pkt.dest}
	ctx := context.Background()

	if pkt.isUDP {
		for _, sniffer := range btPacketSniffers() {
			if sniffer(ctx, metadata, pkt.payload) == nil &&
				metadata.Protocol == C.ProtocolBitTorrent {
				return true, metadata.SniffDetector
			}
		}
		return false, ""
	}
	for _, sniffer := range btStreamSniffers() {
		if sniffer(ctx, metadata, bytes.NewReader(pkt.payload)) == nil &&
			metadata.Protocol == C.ProtocolBitTorrent {
			return true, metadata.SniffDetector
		}
	}
	return false, ""
}

func sniffCapture(path string, maxPackets int) (analysed, detected int, byDetector map[string]int, err error) {
	byDetector = make(map[string]int)
	packets, err := readCapture(path)
	if err != nil {
		return 0, 0, byDetector, err
	}
	for i, pkt := range packets {
		if maxPackets > 0 && i >= maxPackets {
			break
		}
		analysed++
		if ok, detector := sniffOne(pkt); ok {
			detected++
			byDetector[detector]++
		}
	}
	return analysed, detected, byDetector, nil
}

func corpusDir(t testing.TB, which string) string {
	t.Helper()
	dir := filepath.Join("testdata", "pcap", which)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("corpus %s unavailable: %v", which, err)
	}
	return dir
}

// -------------------------------------------------------------- true positive

func TestBitTorrentCorpusTruePositive(t *testing.T) {
	t.Parallel()
	dir := corpusDir(t, "true-positive")

	// Thresholds are set below the measured rate with roughly 10-15 points of
	// headroom. A threshold equal to the observation turns harmless variation
	// into a red test; one far below it stops catching regressions.
	cases := []struct {
		file       string
		minRate    float64
		maxPackets int
		note       string
	}{
		{"own_lsd_bep14.pcap", 90.0, 0, "measured 100%, 2 packets so 90 forces both"},
		{"own_dht_bep5.pcap", 90.0, 0, "measured 100%"},
		{"own_pex_bep11.pcap", 95.0, 600, "measured 100%"},
		{"own_socks5_wrapped_synthetic.pcap", 90.0, 0, "measured 100%: SOCKS5 unwrapping works"},
		{"own_plaintext_bep6_bep10.pcap", 90.0, 400, "measured 100%"},
		{"own_utp_bep29.pcap", 90.0, 600, "measured 100%: every packet in the fixture is uTP"},
		{"own_ipv6_peer.pcap", 90.0, 600, "measured 99.67%"},
		{"own_udp_tracker_bep15.pcap", 80.0, 0, "measured 90%; the one miss is the 16-byte connect response, see udpTrackerResponse"},
		{"bittorrent.pcap", 50.0, 200, "measured 54.50%"},
		{"bittorrent_utp.pcap", 80.0, 100, "measured 89.13%"},
		{"suricata-dht.pcap", 80.0, 50, "measured 100%"},
		{"zeek_tracker.pcap", 40.0, 100, "measured 50.00%, which is the ceiling: see zeek_tracker note below"},
		{"bt_search.pcap", 80.0, 50, "measured 100%"},
		{"targusdataspeed_dht.pcap", 80.0, 50, "measured 100%, DHT on port 5200"},
		{"torrent-dht.pcap", 80.0, 100, "measured 100%"},
		{"bt-http.pcapng", 60.0, 50, "measured 66.67%, which is the ceiling: see bt-http note below"},

		// Rates that are legitimately low, recorded so a future improvement is
		// visible rather than mistaken for a regression.
		{"mippo.pcap", 15.0, 200, "measured 17.65%, mostly tracker and setup traffic"},
		{"bittorrent_tcp_miss.pcapng", 5.0, 100, "measured 6.94%, handshake was not captured"},
		{"bt-dns.pcap", 0.0, 50, "DNS lookups carry no BitTorrent markers"},
		{"tls_torrent.pcapng", 0.0, 50, "TLS-wrapped: 0% is correct, not a defect"},
		{"ustc_bittorrent.pcap", 0.0, 500, "TLS-wrapped research corpus"},

		// See TestMSETrafficRemainsUndetected for why these three are zero.
		{"own_mse_handshake.pcap", 0.0, 400, "MSE handshake, ours"},
		{"own_mid_transfer.pcap", 0.0, 1200, "steady-state MSE traffic, ours"},
		{"own_mse_many_flows.pcap", 5.0, 0, "measured 5.83%: exactly its plaintext flows, none of the 126 MSE ones"},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			analysed, detected, byDetector, err := sniffCapture(filepath.Join(dir, tc.file), tc.maxPackets)
			if err != nil {
				t.Fatalf("%s: %v", tc.file, err)
			}
			if analysed == 0 {
				t.Fatalf("%s: no payload-bearing packets parsed", tc.file)
			}
			rate := float64(detected) / float64(analysed) * 100

			var detectors []string
			for name, n := range byDetector {
				detectors = append(detectors, fmt.Sprintf("%s=%d", name, n))
			}
			sort.Strings(detectors)
			t.Logf("%s (%s): %d/%d = %.2f%% (min %.2f%%) [%s]",
				tc.file, tc.note, detected, analysed, rate, tc.minRate,
				strings.Join(detectors, " "))

			if rate < tc.minRate {
				t.Errorf("detection rate %.2f%% below required %.2f%%", rate, tc.minRate)
			}
		})
	}
}

// Two of the rates above look like detection gaps and are not. Both were
// investigated on 2026-10-22 and both are ceilings, recorded here so nobody
// spends time chasing them:
//
//   bt-http.pcapng (66.67%, 2 of 3)
//     The undetected packet is literally two zero bytes of TCP payload from
//     port 80. There is nothing in it to identify. The two packets that carry
//     anything -- the GET /announce?info_hash=... request and the 307 redirect
//     whose Location repeats the info_hash -- are both detected.
//
//   zeek_tracker.pcap (50%, 1 of 2)
//     The undetected packet is the tracker's response, and it is gzip-compressed
//     (Content-Encoding: gzip, body starts 1f8b0800). The bencode is inside the
//     archive: "5:peers" and "8:complete" appear only after inflating it, and no
//     plaintext marker exists on the wire.
//
//     Decompressing in the sniffer is not worth it, and the reason is not
//     difficulty: the code would never run in production. sing-box sniffs the
//     first packets of an outbound connection, which is the client's request --
//     always detected here -- and does not separately sniff the server's reply
//     on that connection. Inflating untrusted bytes in a VPN core's hot path
//     would also be a decompression-bomb vector for no operational gain.
//
// The contrast with the uTP finding is the point: a low number is sometimes a
// bug and sometimes the honest answer, and the only way to tell is to look at
// the packets.

// ------------------------------------------------------------- false positive

// TestBitTorrentCorpusFalsePositive is the reason the 650-capture corpus is
// worth its disk space: it is what makes a change to the sniffers safe to
// make. Any loosening that starts eating Kerberos, TLS or SSH shows up here
// instead of in production.
func TestBitTorrentCorpusFalsePositive(t *testing.T) {
	t.Parallel()
	dir := corpusDir(t, "false-positive")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	// Detections that are accepted, each with the reason it is not a bug to
	// fix. Anything not listed here fails the test.
	allowed := map[string]string{
		// Not a false positive at all: this capture really does carry
		// BitTorrent DHT on port 6881, so detecting it is correct. nDPI ships
		// it under a name about IPv6 caches, and the standalone
		// BitTorrentBlocker project documented the same 18 detections.
		"lru_ipv6_caches.pcapng": "capture genuinely contains BitTorrent DHT on port 6881",
	}

	var captures, clean, unparseable int
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".pcap") && !strings.HasSuffix(name, ".pcapng") {
			continue
		}
		captures++
		analysed, detected, byDetector, err := sniffCapture(filepath.Join(dir, name), 0)
		if err != nil {
			unparseable++
			continue
		}
		if analysed == 0 || detected == 0 {
			clean++
			continue
		}
		if reason, ok := allowed[name]; ok {
			t.Logf("%s: %d/%d detections, allowed: %s", name, detected, analysed, reason)
			continue
		}
		var detectors []string
		for d, n := range byDetector {
			detectors = append(detectors, fmt.Sprintf("%s=%d", d, n))
		}
		sort.Strings(detectors)
		t.Errorf("FALSE POSITIVE %s: %d of %d packets detected as BitTorrent [%s]",
			name, detected, analysed, strings.Join(detectors, " "))
	}
	t.Logf("%d captures seen, %d clean, %d unparseable", captures, clean, unparseable)
	if captures < 500 {
		t.Errorf("only %d captures seen; corpus looks truncated", captures)
	}
	// A corpus that suddenly stops parsing would otherwise read as success.
	if parsed := captures - unparseable; parsed < 500 {
		t.Errorf("only %d of %d captures actually parsed; the sweep is not "+
			"covering what it claims to", parsed, captures)
	}
}

// --------------------------------------------------------------------- MSE

// TestMSETrafficRemainsUndetected records that MSE-encrypted BitTorrent is not
// detected, and that this is a known gap rather than an accident.
//
// BitTorrentMSE was removed on 2026-10-22. It had never fired, and not because
// a threshold needed loosening: the function was self-contradictory. Phases 1
// and 2 required near-random data -- at least 92 distinct bytes out of 96 and
// Shannon entropy above 6.5 -- while phase 3 then required a run of eight zero
// bytes in the following ~530. Random data contains such a run with
// probability about 2.9e-17, so the two halves could never hold at once.
// Measured on own_mse_many_flows.pcap it fired on 0 of 284 encrypted payloads,
// and across 20000 random 96-byte windows the best observed were 91 distinct
// bytes and 6.481 entropy, both short of the gate.
//
// Loosening it was measured and rejected: every variant that caught all 126
// real MSE flows also flagged 16-19 captures in the false-positive corpus,
// consistently ethereum, kerberos, zabbix and telegram_videocall, which also
// open with cryptographic random material. nDPI does not attempt MSE detection
// either; it has a generic fully-encrypted heuristic that reports a flow risk,
// runs only on traffic no dissector claimed, and is opt-in. See
// testdata/pcap/NOTICE.md.
//
// This test keeps the gap visible. If MSE detection is ever implemented these
// fixtures will score above zero and it will fail, which is the point to raise
// the thresholds in TestBitTorrentCorpusTruePositive and update the notice.
func TestMSETrafficRemainsUndetected(t *testing.T) {
	t.Parallel()
	dir := corpusDir(t, "true-positive")

	for _, name := range []string{"own_mse_handshake.pcap", "own_mid_transfer.pcap"} {
		analysed, detected, _, err := sniffCapture(filepath.Join(dir, name), 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if analysed == 0 {
			t.Fatalf("%s: nothing parsed", name)
		}
		t.Logf("%s: %d/%d detected", name, detected, analysed)
		if detected != 0 {
			t.Errorf("%s: %d of %d packets detected, but MSE detection is not "+
				"implemented. If that changed deliberately, raise the "+
				"thresholds and update NOTICE.md", name, detected, analysed)
		}
	}

	// The mixed fixture must still detect its plaintext flows, so this test
	// cannot pass merely because the sniffers stopped working altogether.
	analysed, detected, _, err := sniffCapture(filepath.Join(dir, "own_mse_many_flows.pcap"), 0)
	if err != nil {
		t.Fatalf("own_mse_many_flows.pcap: %v", err)
	}
	t.Logf("own_mse_many_flows.pcap: %d/%d detected (its plaintext subset)", detected, analysed)
	if detected == 0 {
		t.Error("own_mse_many_flows.pcap detected nothing at all; it contains 25 " +
			"plaintext handshakes that must still be caught")
	}
}

// TestBitTorrentMessageRejectsShortBitfield is a regression test for the one
// false positive the corpus sweep found in production logic.
//
// These bytes are a real packet from testdata/pcap/false-positive/netflix.pcap:
// plain HTTP video delivery from port 80, one of 911 packets in that capture.
// They parse as msgLen=3, msgID=5, which the Bitfield branch used to accept on
// nothing more than "small length, fifth byte is 0x05" -- its own guards only
// covered msgLen 8..12 and msgLen > 40. In production that meant a dropped
// connection and a one-minute XDP ban on a CDN address.
//
// What rejects it now is the chain check: the bitfield ends at offset 7 and the
// following four bytes are 0x3b000000, a length of ~989 MB, so the stream does
// not continue as BitTorrent.
func TestBitTorrentMessageRejectsShortBitfield(t *testing.T) {
	t.Parallel()

	payload, err := hex.DecodeString(
		"000000030546063b0000000002e5a4080101010000000306")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	var metadata adapter.InboundContext
	if err := sniff.BitTorrentMessage(context.Background(), &metadata,
		bytes.NewReader(payload)); err == nil {
		t.Errorf("HTTP video payload accepted as a BitTorrent Bitfield message; "+
			"detector %q", metadata.SniffDetector)
	}

	// A genuine bitfield whose message fills the segment exactly must still be
	// accepted, so the fix is not simply refusing short bitfields.
	genuine := []byte{0x00, 0x00, 0x00, 0x03, 0x05, 0xF0, 0x0F}
	metadata = adapter.InboundContext{}
	if err := sniff.BitTorrentMessage(context.Background(), &metadata,
		bytes.NewReader(genuine)); err != nil {
		t.Errorf("a bitfield that exactly fills the segment was rejected: %v", err)
	}
}

// TestSnifferListsMatchProduction guards the one assumption the corpus tests
// rest on: that btStreamSniffers and btPacketSniffers above are the same set
// the router installs for sniffer name "bittorrent".
//
// Those lists are copies. Without this check, adding a sniffer to
// RuleActionSniff.build() would leave the corpus silently not covering it --
// every test would still pass, while the new detector went unexercised against
// 650 captures. That is the same class of failure as the pcap reader that used
// to skip the whole sweep on one malformed file: a green test that checks less
// than it appears to.
//
// The comparison goes through NewRuleAction rather than re-reading the source,
// so it exercises the real expansion. Go cannot compare function values, so the
// identity used is the code pointer from reflect.
func TestSnifferListsMatchProduction(t *testing.T) {
	t.Parallel()

	action, err := rule.NewRuleAction(logger.NOP(), option.RuleAction{
		Action: C.RuleActionTypeSniff,
		SniffOptions: option.RouteActionSniff{
			Sniffer: badoption.Listable[string]{C.ProtocolBitTorrent},
		},
	})
	if err != nil {
		t.Fatalf("build sniff action: %v", err)
	}
	sniffAction, ok := action.(*rule.RuleActionSniff)
	if !ok {
		t.Fatalf("unexpected action type %T", action)
	}

	streamNames := func(fns []sniff.StreamSniffer) []string {
		out := make([]string, 0, len(fns))
		for _, fn := range fns {
			out = append(out, funcName(reflect.ValueOf(fn).Pointer()))
		}
		sort.Strings(out)
		return out
	}
	packetNames := func(fns []sniff.PacketSniffer) []string {
		out := make([]string, 0, len(fns))
		for _, fn := range fns {
			out = append(out, funcName(reflect.ValueOf(fn).Pointer()))
		}
		sort.Strings(out)
		return out
	}

	if got, want := streamNames(sniffAction.StreamSniffers), streamNames(btStreamSniffers()); !slices.Equal(got, want) {
		t.Errorf("stream sniffer drift.\n  production: %v\n  test list:  %v\n"+
			"Update btStreamSniffers in this file, then decide what fixture "+
			"covers the new detector.", got, want)
	}
	if got, want := packetNames(sniffAction.PacketSniffers), packetNames(btPacketSniffers()); !slices.Equal(got, want) {
		t.Errorf("packet sniffer drift.\n  production: %v\n  test list:  %v\n"+
			"Update btPacketSniffers in this file, then decide what fixture "+
			"covers the new detector.", got, want)
	}
	t.Logf("in sync: %d stream, %d packet sniffers",
		len(sniffAction.StreamSniffers), len(sniffAction.PacketSniffers))
}

func funcName(pc uintptr) string {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}
	name := fn.Name()
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return name
}
