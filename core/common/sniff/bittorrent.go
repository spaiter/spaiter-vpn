package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

func setBitTorrentProtocol(metadata *adapter.InboundContext, detector string) {
	metadata.Protocol = C.ProtocolBitTorrent
	metadata.SniffDetector = detector
}

// BitTorrent detects if the stream is a BitTorrent connection.
// For the BitTorrent protocol specification, see https://www.bittorrent.org/beps/bep_0003.html
func BitTorrent(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var first byte
	err := binary.Read(reader, binary.BigEndian, &first)
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}

	if first != 19 {
		return os.ErrInvalid
	}

	const header = "BitTorrent protocol"
	var protocol [19]byte
	var n int
	n, err = reader.Read(protocol[:])
	if string(protocol[:n]) != header[:n] {
		return os.ErrInvalid
	}
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}
	if n < 19 {
		return ErrNeedMoreData
	}

	setBitTorrentProtocol(metadata, "handshake")
	return nil
}

// UTP detects if the packet is a uTP connection packet with robust false positive rejection.
// For the uTP protocol specification, see https://www.bittorrent.org/beps/bep_0029.html
func UTP(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if len(packet) < 20 {
		return os.ErrInvalid
	}

	// Reject DHCP/BOOTP packets (RFC 2131)
	if len(packet) >= 240 {
		op := packet[0]
		htype := packet[1]
		hlen := packet[2]
		if (op == 0x01 || op == 0x02) && htype == 0x01 && hlen == 0x06 {
			if packet[236] == 0x63 && packet[237] == 0x82 && packet[238] == 0x53 && packet[239] == 0x63 {
				return os.ErrInvalid
			}
		}
	}

	// Reject modern STUN (RFC 5389) — magic cookie at offset 4-7
	if len(packet) >= 8 {
		if packet[4] == 0x21 && packet[5] == 0x12 && packet[6] == 0xA4 && packet[7] == 0x42 {
			return os.ErrInvalid
		}
	}

	// Reject classic STUN (RFC 3489) — known binding message types
	if len(packet) >= 20 {
		msgType := binary.BigEndian.Uint16(packet[0:2])
		msgLen := binary.BigEndian.Uint16(packet[2:4])
		if msgType < 0x4000 && msgLen < 1500 {
			if msgType == 0x0001 || msgType == 0x0101 || msgType == 0x0111 ||
				msgType == 0x0002 || msgType == 0x0102 || msgType == 0x0112 {
				return os.ErrInvalid
			}
		}
	}

	// Reject DTLS packets — DTLS versions at offset 5-6
	if len(packet) >= 7 {
		version := binary.BigEndian.Uint16(packet[5:7])
		if version == 0xFEFF || version == 0xFEFD || version == 0xFEFC {
			return os.ErrInvalid
		}
	}

	// Validate uTP version and type
	version := packet[0] & 0x0F
	typ := packet[0] >> 4
	if version != 1 || typ > 4 {
		return os.ErrInvalid
	}

	connectionID := binary.BigEndian.Uint16(packet[2:4])
	windowSize := binary.BigEndian.Uint32(packet[12:16])

	// Reject zero connection ID for non-SYN packets
	if connectionID == 0 && typ != 4 {
		return os.ErrInvalid
	}

	// Reject unrealistically large window sizes
	if windowSize > maxUTPWindowSize {
		return os.ErrInvalid
	}

	// Reject WireGuard handshake initiation: type=0 with 0x00 0x00 0x00 reserved
	if typ == 0 && len(packet) >= 4 {
		if packet[1] == 0x00 && packet[2] == 0x00 && packet[3] == 0x00 {
			return os.ErrInvalid
		}
	}

	// Sanity-bound the timestamp difference. A uTP peer reports the measured
	// one-way delay here, so a value of half an hour in microseconds is not a
	// real measurement.
	//
	// There used to be two further rules in this block, rejecting a packet when
	// timestamp_difference_microseconds contained three or four zero bytes, on
	// the theory that VoIP and messaging protocols would show that pattern.
	// They were removed on 2026-10-22: that field is legitimately zero in uTP,
	// both on the first packets of a connection and whenever no delay sample
	// has been taken yet, so the rules punished the protocol they were meant to
	// identify. Measured on own_utp_bep29.pcap they rejected 279 of 600
	// genuine uTP packets -- detection went from 53.50% to 100.00% once they
	// were gone.
	//
	// Nothing was lost by removing them. The false-positive corpus stayed at
	// 648 clean captures of 649 parseable, and that corpus contains
	// telegram_videocall, telegram_voice, zoom, teams, webex, discord_call,
	// whatsapp and wa_voice: the VoIP traffic those rules were aimed at is
	// already rejected by the STUN magic-cookie, classic-STUN and DTLS checks
	// above, which is what VoIP actually looks like on the wire.
	if typ == 0 || typ == 1 {
		if binary.BigEndian.Uint32(packet[8:12]) > 2000000000 {
			return os.ErrInvalid
		}
	}

	// Validate initial extension field (must be 0-4 per BEP 29)
	extension := packet[1]
	if extension > 4 {
		return os.ErrInvalid
	}

	// Walk extension linked list
	offset := 20
	for extension != 0 {
		if offset >= len(packet) {
			return os.ErrInvalid
		}
		nextExtension := packet[offset]
		offset++
		if nextExtension > 4 {
			return os.ErrInvalid
		}
		if offset >= len(packet) {
			return os.ErrInvalid
		}
		length := int(packet[offset])
		offset++
		extension = nextExtension
		offset += length
		if offset > len(packet) {
			return os.ErrInvalid
		}
	}

	setBitTorrentProtocol(metadata, "utp")
	return nil
}

// UDPTracker detects if the packet is a UDP Tracker Protocol packet with deep validation.
// For the UDP Tracker Protocol specification, see https://www.bittorrent.org/beps/bep_0015.html
// udpTrackerResponse detects the tracker-to-client side of BEP 15.
//
// UDPTracker below only recognises requests: connect by its magic constant,
// announce and scrape by connection_id plus action. Responses have a different
// layout with no magic and no connection_id, so half of a tracker exchange went
// undetected -- measured as exactly 5 of 10 packets on
// testdata/pcap/true-positive/own_udp_tracker_bep15.pcap.
//
// Detecting the response side matters because UDP has no connection to drop:
// each datagram stands alone, so a missed request is simply missed. Catching
// the reply still identifies the tracker and gets its address banned, which is
// what stops further announces.
//
// The checks are deliberately strict, because the response signatures are
// otherwise weak -- an announce response begins with four bytes 00 00 00 01 and
// little else. Structural constraints carry the weight: the peer list length
// must be an exact multiple of 6, and the interval and counters must be
// plausible. The connect response is NOT detected at all: it is 16 bytes
// starting with four zero bytes, which is far too generic to claim.
//
// This runs before UDPTracker's DNS exclusion on purpose. That exclusion reads
// packet[4:6] as a DNS question count, but in an announce response those bytes
// are the top half of a random transaction_id, so a legitimate response would
// often be discarded as DNS.
func udpTrackerResponse(metadata *adapter.InboundContext, packet []byte) bool {
	if len(packet) < 8 {
		return false
	}
	action := binary.BigEndian.Uint32(packet[0:4])

	switch action {
	case actionAnnounce:
		// action | transaction_id | interval | leechers | seeders | peers*6
		if len(packet) < 20 || (len(packet)-20)%6 != 0 {
			return false
		}
		interval := binary.BigEndian.Uint32(packet[8:12])
		if interval == 0 || interval > 86400 {
			return false
		}
		leechers := binary.BigEndian.Uint32(packet[12:16])
		seeders := binary.BigEndian.Uint32(packet[16:20])
		if leechers > 1_000_000 || seeders > 1_000_000 {
			return false
		}
		// A peer entry with a zero port is not a peer.
		for off := 20; off+6 <= len(packet); off += 6 {
			if binary.BigEndian.Uint16(packet[off+4:off+6]) == 0 {
				return false
			}
		}
		setBitTorrentProtocol(metadata, "udp-tracker-announce-response")
		return true

	case actionScrape:
		// action | transaction_id | (complete | downloaded | incomplete)*n
		if len(packet) < 20 || (len(packet)-8)%12 != 0 {
			return false
		}
		for off := 8; off+12 <= len(packet); off += 12 {
			for field := 0; field < 3; field++ {
				at := off + field*4
				if binary.BigEndian.Uint32(packet[at:at+4]) > 10_000_000 {
					return false
				}
			}
		}
		setBitTorrentProtocol(metadata, "udp-tracker-scrape-response")
		return true

	case actionError:
		// action | transaction_id | human-readable message
		if len(packet) < 12 {
			return false
		}
		for _, b := range packet[8:] {
			if b != '\t' && b != '\n' && b != '\r' && (b < 0x20 || b > 0x7E) {
				return false
			}
		}
		setBitTorrentProtocol(metadata, "udp-tracker-error-response")
		return true
	}
	return false
}

func UDPTracker(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	// Responses are checked first; see udpTrackerResponse for why the ordering
	// matters against the DNS exclusion below.
	if udpTrackerResponse(metadata, packet) {
		return nil
	}

	if len(packet) < minSizeConnect {
		return os.ErrInvalid
	}

	// Reject DNS queries and responses
	if len(packet) >= 12 {
		flags := binary.BigEndian.Uint16(packet[2:4])
		qdcount := binary.BigEndian.Uint16(packet[4:6])
		isQuery := (flags&0x8000) == 0 && qdcount > 0 && qdcount < 100
		isResponse := (flags & 0x8000) != 0
		if isQuery || isResponse {
			opcode := (flags >> 11) & 0x0F
			if opcode <= 2 {
				return os.ErrInvalid
			}
		}
	}

	// Reject CAPWAP control packets
	if packet[0] == 0x00 && (packet[1] == 0x10 || packet[1] == 0x20 || packet[1] == 0x00) {
		if len(packet) >= 14 && packet[12] == 0x00 && packet[13] == 0x00 {
			return os.ErrInvalid
		}
	}

	// Reject DTLS packets
	if len(packet) >= 3 {
		contentType := packet[0]
		dtlsVersion := binary.BigEndian.Uint16(packet[1:3])
		if (contentType >= 0x14 && contentType <= 0x17) &&
			(dtlsVersion == 0xFEFF || dtlsVersion == 0xFEFD || dtlsVersion == 0xFEFC) {
			return os.ErrInvalid
		}
	}

	// Reject AFS RX protocol packets
	if len(packet) >= 24 {
		epoch := binary.BigEndian.Uint32(packet[0:4])
		callNum := binary.BigEndian.Uint32(packet[8:12])
		seq := binary.BigEndian.Uint32(packet[12:16])
		serial := binary.BigEndian.Uint32(packet[16:20])
		packetType := packet[20]
		if epoch >= 0x50000000 &&
			callNum <= 100 &&
			seq <= 1000 &&
			serial <= 1000 &&
			packetType >= 1 && packetType <= 13 {
			return os.ErrInvalid
		}
	}

	// 1. Connect (Magic Number Check)
	if len(packet) >= minSizeConnect && len(packet) < minSizeScrape {
		if binary.BigEndian.Uint64(packet[:8]) == trackerProtocolID &&
			binary.BigEndian.Uint32(packet[8:12]) == actionConnect {
			setBitTorrentProtocol(metadata, "udp-tracker-connect")
			return nil
		}
	}

	// 2. Announce (Action + PeerID Check)
	if len(packet) >= minSizeAnnounce {
		action := binary.BigEndian.Uint32(packet[8:12])
		if action == actionAnnounce {
			connectionID := binary.BigEndian.Uint64(packet[:8])
			if connectionID == 0 || connectionID == trackerProtocolID {
				return os.ErrInvalid
			}
			if countTrailingZeroBytes(packet[:8]) > 3 {
				return os.ErrInvalid
			}

			// Check PeerID at offset 36
			peerID := packet[36:40]
			for _, prefix := range peerIDPrefixes {
				if bytes.HasPrefix(peerID, prefix) {
					setBitTorrentProtocol(metadata, "udp-tracker-announce-peer-id")
					return nil
				}
			}

			// Without known peer ID prefix, validate info_hash
			infoHash := packet[16:36]
			allZero := true
			allFF := true
			for _, b := range infoHash {
				if b != 0 {
					allZero = false
				}
				if b != 0xFF {
					allFF = false
				}
				if !allZero && !allFF {
					break
				}
			}
			if allZero || allFF {
				return os.ErrInvalid
			}

			// Reject excessive trailing zeros in peer ID
			if countTrailingZeroBytes(packet[36:56]) > 3 {
				return os.ErrInvalid
			}

			setBitTorrentProtocol(metadata, "udp-tracker-announce")
			return nil
		}
	}

	// 3. Scrape
	if len(packet) >= minSizeScrape {
		action := binary.BigEndian.Uint32(packet[8:12])
		if action == actionScrape {
			connectionID := binary.BigEndian.Uint64(packet[:8])
			if connectionID == 0 || connectionID == trackerProtocolID {
				return os.ErrInvalid
			}
			if countTrailingZeroBytes(packet[:8]) > 3 {
				return os.ErrInvalid
			}
			setBitTorrentProtocol(metadata, "udp-tracker-scrape")
			return nil
		}
	}

	return os.ErrInvalid
}

// BitTorrentDHTPacket detects BitTorrent DHT packets (bencode dictionary + node validation).
func BitTorrentDHTPacket(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if checkBencodeDHT(packet) {
		setBitTorrentProtocol(metadata, "dht")
		return nil
	}
	return os.ErrInvalid
}

// BitTorrentLSD detects Local Service Discovery (BEP 26) multicast traffic.
func BitTorrentLSD(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	// Check destination address and port
	if metadata.Destination.Port == 6771 && metadata.Destination.Addr.IsValid() {
		dest := metadata.Destination.Addr
		if dest == netip.AddrFrom4([4]byte{239, 192, 152, 143}) {
			setBitTorrentProtocol(metadata, "lsd-ipv4-multicast")
			return nil
		}
		lsdIPv6, _ := netip.AddrFromSlice([]byte{0xff, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xef, 0xc0, 0x98, 0x8f})
		if dest == lsdIPv6 {
			setBitTorrentProtocol(metadata, "lsd-ipv6-multicast")
			return nil
		}
	}

	// Check payload for LSD message patterns
	if bytes.Contains(packet, []byte("BT-SEARCH * HTTP/1.1")) {
		setBitTorrentProtocol(metadata, "lsd-bt-search")
		return nil
	}
	if bytes.Contains(packet, []byte("Host: 239.192.152.143:6771")) {
		setBitTorrentProtocol(metadata, "lsd-host")
		return nil
	}
	if bytes.Contains(packet, []byte("Infohash: ")) &&
		bytes.Contains(packet, []byte("Port: ")) {
		setBitTorrentProtocol(metadata, "lsd-infohash-port")
		return nil
	}

	return os.ErrInvalid
}

// BitTorrentSignaturePacket detects BitTorrent UDP packets by signature matching.
func BitTorrentSignaturePacket(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if checkSignatures(packet) {
		setBitTorrentProtocol(metadata, "signature-packet")
		return nil
	}
	return os.ErrInvalid
}

// BitTorrentMessage detects BitTorrent TCP message structure (length-prefixed messages).
func BitTorrentMessage(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var header [53]byte
	n, _ := io.ReadFull(reader, header[:5])
	if n < 5 {
		return os.ErrInvalid
	}

	// Read more if we need it (up to 53 bytes for piece SSH rejection)
	total := 5
	if n == 5 {
		extra, _ := reader.Read(header[5:])
		total += extra
	}

	payload := header[:total]
	if !checkBitTorrentMessage(payload) {
		return os.ErrInvalid
	}

	setBitTorrentProtocol(metadata, "message")
	return nil
}

// BitTorrentFAST detects FAST Extension messages (BEP 6).
func BitTorrentFAST(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var header [5]byte
	n, _ := io.ReadFull(reader, header[:])
	if n < 5 {
		return os.ErrInvalid
	}

	if !checkFASTExtension(header[:]) {
		return os.ErrInvalid
	}

	setBitTorrentProtocol(metadata, "fast")
	return nil
}

// BitTorrentExtended detects BitTorrent Extension Protocol messages (BEP 10).
func BitTorrentExtended(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var header [7]byte
	n, _ := io.ReadFull(reader, header[:])
	if n < 7 {
		return os.ErrInvalid
	}

	if !checkExtendedMessage(header[:]) {
		return os.ErrInvalid
	}

	setBitTorrentProtocol(metadata, "extended")
	return nil
}

// BitTorrentHTTP detects HTTP-based BitTorrent protocols (WebSeed, Bitcomet, User-Agent).
func BitTorrentHTTP(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var buf [512]byte
	n, _ := io.ReadAtLeast(reader, buf[:], 16)
	if n < 16 {
		return os.ErrInvalid
	}

	if !checkHTTPBitTorrent(buf[:n]) {
		return os.ErrInvalid
	}

	setBitTorrentProtocol(metadata, "http")
	return nil
}

// BitTorrentSignature detects BitTorrent TCP streams by signature matching.
func BitTorrentSignature(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var buf [512]byte
	n, _ := io.ReadAtLeast(reader, buf[:], 4)
	if n < 4 {
		return os.ErrInvalid
	}

	if !checkSignatures(buf[:n]) {
		return os.ErrInvalid
	}

	setBitTorrentProtocol(metadata, "signature-stream")
	return nil
}

// --- Helper functions ---

// countTrailingZeroBytes counts trailing zero bytes in a byte slice.
func countTrailingZeroBytes(data []byte) int {
	count := 0
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0 {
			count++
		} else {
			break
		}
	}
	return count
}

// parseBencodeLength parses a decimal length from bencode with overflow protection.
func parseBencodeLength(data []byte) int {
	const maxLen = 1 << 20 // 1MB cap
	n := 0
	for _, ch := range data {
		if ch < '0' || ch > '9' {
			continue
		}
		n = n*10 + int(ch-'0')
		if n > maxLen {
			return 0
		}
	}
	return n
}

// checkDHTNodes validates DHT node list binary structure.
// IPv4 nodes: 26 bytes per node (20-byte ID + 4-byte IP + 2-byte port)
// IPv6 nodes: 38 bytes per node (20-byte ID + 16-byte IP + 2-byte port)
func checkDHTNodes(payload []byte) bool {
	// Check for IPv4 nodes list: "6:nodes<len>:<data>"
	nodesIdx := bytes.Index(payload, []byte("6:nodes"))
	if nodesIdx != -1 && nodesIdx+7 < len(payload) {
		offset := nodesIdx + 7
		colonIdx := bytes.IndexByte(payload[offset:], ':')
		if colonIdx != -1 && colonIdx > 0 && colonIdx < 10 {
			nodeDataLen := parseBencodeLength(payload[offset : offset+colonIdx])
			if nodeDataLen >= 26 && nodeDataLen%26 == 0 {
				return true
			}
		}
	}

	// Check for IPv6 nodes list: "7:nodes6<len>:<data>"
	nodes6Idx := bytes.Index(payload, []byte("7:nodes6"))
	if nodes6Idx != -1 && nodes6Idx+8 < len(payload) {
		offset := nodes6Idx + 8
		colonIdx := bytes.IndexByte(payload[offset:], ':')
		if colonIdx != -1 && colonIdx > 0 && colonIdx < 10 {
			nodeDataLen := parseBencodeLength(payload[offset : offset+colonIdx])
			if nodeDataLen >= 38 && nodeDataLen%38 == 0 {
				return true
			}
		}
	}

	return false
}

// checkBencodeDHT looks for structural Bencode dictionary patterns with DHT validation.
func checkBencodeDHT(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	if payload[0] != 'd' || payload[len(payload)-1] != 'e' {
		return false
	}

	// Check for Suricata-specific prefixes
	if bytes.HasPrefix(payload, []byte("d1:ad")) ||
		bytes.HasPrefix(payload, []byte("d1:rd")) ||
		bytes.HasPrefix(payload, []byte("d2:ip")) ||
		bytes.HasPrefix(payload, []byte("d1:el")) {
		return true
	}

	// Must contain query/response/error type
	hasQuery := bytes.Contains(payload, []byte("1:y1:q"))
	hasResponse := bytes.Contains(payload, []byte("1:y1:r"))
	hasError := bytes.Contains(payload, []byte("1:y1:e"))
	if !hasQuery && !hasResponse && !hasError {
		return false
	}

	hasDHTMethod := bytes.Contains(payload, []byte("4:ping")) ||
		bytes.Contains(payload, []byte("9:find_node")) ||
		bytes.Contains(payload, []byte("9:get_peers")) ||
		bytes.Contains(payload, []byte("13:announce_peer")) ||
		bytes.Contains(payload, []byte("3:get")) ||
		bytes.Contains(payload, []byte("3:put"))

	// Check for transaction ID AND (DHT method OR DHT-specific fields)
	if bytes.Contains(payload, []byte("1:t")) {
		if hasQuery {
			return hasDHTMethod
		}
		return hasDHTMethod ||
			checkDHTNodes(payload) ||
			bytes.Contains(payload, []byte("6:values")) ||
			bytes.Contains(payload, []byte("5:token"))
	}

	if checkDHTNodes(payload) {
		return true
	}

	return false
}

// checkSignatures searches for BitTorrent signature patterns in payload.
func checkSignatures(payload []byte) bool {
	// Fast-path: most common signatures
	if bytes.Contains(payload, []byte("BitTorrent protocol")) {
		return true
	}

	// DHT queries/responses fast-path
	if len(payload) >= 13 && payload[0] == 'd' && payload[1] == '1' && payload[2] == ':' {
		if payload[3] == 'a' || payload[3] == 'r' {
			if payload[4] == 'd' && payload[5] == '2' && payload[6] == ':' {
				return true
			}
		}
	}

	// Check remaining signatures (skip indices 0 and 1, already checked)
	for _, sig := range btSignatures[2:] {
		if len(sig) > len(payload) {
			continue
		}
		if bytes.Contains(payload, sig) {
			return true
		}
	}
	return false
}

// checkExtendedMessage detects BitTorrent Extension Protocol messages (BEP 10).
func checkExtendedMessage(payload []byte) bool {
	if len(payload) < 7 {
		return false
	}
	// Validate message length (bytes 0-3): must be plausible for a BT message.
	// Encrypted traffic (e.g. Telegram MTProto) can have 0x14 at byte 4 by chance,
	// but the preceding 4-byte length will almost never fall in the valid BT range.
	msgLen := binary.BigEndian.Uint32(payload[0:4])
	if msgLen < 2 || msgLen > 131072 {
		return false
	}
	// Message ID 20 (0x14) at offset 4
	if payload[4] == 0x14 {
		extID := payload[5]
		if extID == 0 {
			// Extended handshake must begin with a bencode dictionary
			return len(payload) > 6 && payload[6] == 'd'
		}
		return true
	}
	return false
}

// checkFASTExtension detects FAST Extension messages (BEP 6).
func checkFASTExtension(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	msgID := payload[4]
	if msgID >= 0x0D && msgID <= 0x11 {
		msgLen := binary.BigEndian.Uint32(payload[0:4])
		switch msgID {
		case 0x0D, 0x11: // Suggest Piece, Allowed Fast — 5 bytes
			return msgLen == 5
		case 0x0E, 0x0F: // Have All, Have None — 1 byte
			return msgLen == 1
		case 0x10: // Reject Request — 13 bytes
			return msgLen == 13
		}
		return true
	}
	return false
}

// checkHTTPBitTorrent detects HTTP-based BitTorrent protocols.
func checkHTTPBitTorrent(payload []byte) bool {
	if len(payload) < 16 {
		return false
	}
	if !bytes.HasPrefix(payload, []byte("GET ")) {
		return false
	}

	if bytes.Contains(payload, []byte("/webseed?info_hash=")) {
		return true
	}
	if bytes.Contains(payload, []byte("/data?fid=")) && bytes.Contains(payload, []byte("&size=")) {
		return true
	}
	if bytes.Contains(payload, []byte("User-Agent: Azureus")) ||
		bytes.Contains(payload, []byte("User-Agent: BitTorrent")) ||
		bytes.Contains(payload, []byte("User-Agent: BTWebClient")) ||
		bytes.Contains(payload, []byte("User-Agent: FlashGet")) {
		return true
	}
	// Shareaza with Gnutella exclusion
	if bytes.Contains(payload, []byte("User-Agent: Shareaza")) {
		if bytes.Contains(payload, []byte("GNUTELLA/")) {
			return false
		}
		return true
	}

	return false
}

// checkBitTorrentMessage detects BitTorrent TCP messages by structure.
// messageChainPlausible reports whether the bytes after a BitTorrent message
// ending at offset end continue to look like a BitTorrent stream.
//
// Peer-wire messages are length-prefixed and chained, so in a real session a
// message is followed by the end of the segment or by another well-formed
// message. Arbitrary binary data almost never produces two valid frames in a
// row, which makes this a cheap discriminator for the branches whose own
// length check is too permissive to stand alone.
//
// It is deliberately generous about truncation: TCP segmentation can cut a
// message anywhere, so fewer than four trailing bytes is accepted rather than
// treated as malformed.
func messageChainPlausible(payload []byte, end int) bool {
	if end < 0 || end > len(payload) {
		return false
	}
	rest := payload[end:]
	switch {
	case len(rest) == 0:
		return true // the message exactly fills the segment
	case len(rest) < 4:
		return true // next length prefix was split across segments
	}

	nextLen := binary.BigEndian.Uint32(rest[:4])
	if nextLen == 0 {
		return true // keep-alive, which is a valid next frame
	}
	if nextLen > 262144 {
		return false
	}
	if len(rest) >= 5 {
		// Message ids above the BitTorrent v2 hash range are not part of any
		// BEP this sniffer claims to understand.
		if rest[4] > 23 {
			return false
		}
	}
	return true
}

func checkBitTorrentMessage(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}

	msgID := payload[4]

	// Reject SSH ranges (50+)
	if msgID >= 50 {
		return false
	}

	// SSH transport layer (21-49): only accept BT v2 hash messages (21-23)
	if msgID >= 21 && msgID <= 49 {
		if msgID > 23 {
			return false
		}
	}

	msgLen := binary.BigEndian.Uint32(payload[0:4])
	if msgLen == 0 || msgLen > 262144 {
		return false
	}

	expectedLen := int(msgLen) + 4
	if expectedLen > len(payload)*10 {
		return false
	}

	switch msgID {
	case 0x00, 0x01, 0x02, 0x03: // Choke, Unchoke, Interested, Not Interested
		return msgLen == 1

	case 0x04: // Have
		return msgLen == 5

	case 0x05: // Bitfield
		if msgLen <= 1 || msgLen > 65536 {
			return false
		}
		// Reject short bitfields that look like protocol messages (MSDO, SSH)
		if msgLen >= 8 && msgLen <= 12 {
			if len(payload) >= 9 {
				data := payload[5:]
				ffCount := 0
				zeroCount := 0
				for _, b := range data {
					if b == 0xFF {
						ffCount++
					} else if b == 0x00 {
						zeroCount++
					}
				}
				if (ffCount + zeroCount) >= len(data)*6/10 {
					return false
				}
			}
		}
		// Reject encrypted SSH packets (high unique byte count)
		if len(payload) >= 20 && msgLen > 40 {
			sample := payload[5:21]
			var seen [256]bool
			uniqueCount := 0
			repeatedCount := 0
			prevByte := sample[0]
			for _, b := range sample {
				if !seen[b] {
					seen[b] = true
					uniqueCount++
				}
				if b == prevByte {
					repeatedCount++
				}
				prevByte = b
			}
			if uniqueCount >= 13 && repeatedCount <= 4 {
				return false
			}
		}
		// The guards above only cover msgLen 8..12 and msgLen > 40, so a short
		// bitfield was accepted on nothing more than "first four bytes are a
		// small integer and the fifth is 0x05". That is weak enough for
		// ordinary binary traffic to hit: one packet in 911 of plain HTTP
		// video delivery in testdata netflix.pcap matched with msgLen=3, and in
		// production the reject rule then drops the connection and XDP-bans the
		// CDN address. Require the surrounding stream to look like BitTorrent
		// as well.
		return messageChainPlausible(payload, 4+int(msgLen))

	case 0x06: // Request
		return msgLen == 13

	case 0x07: // Piece
		if msgLen <= 9 || msgLen > 16393 {
			return false
		}
		// Reject SSH key exchange (high ASCII + commas/hyphens)
		if len(payload) >= 50 {
			sampleStart := 13
			if sampleStart+40 <= len(payload) {
				sample := payload[sampleStart : sampleStart+40]
				printableCount := 0
				commaCount := 0
				for _, b := range sample {
					if b >= 0x20 && b <= 0x7E {
						printableCount++
						if b == ',' || b == '-' {
							commaCount++
						}
					}
				}
				if printableCount >= 30 && commaCount >= 3 {
					return false
				}
			}
		}
		return true

	case 0x08: // Cancel
		return msgLen == 13

	case 0x09: // Port (DHT)
		return msgLen == 3

	case 0x0D: // Suggest Piece (BEP 6)
		return msgLen == 5

	case 0x0E, 0x0F: // Have All, Have None (BEP 6)
		return msgLen == 1

	case 0x10: // Reject Request (BEP 6)
		return msgLen == 13

	case 0x11: // Allowed Fast (BEP 6)
		return msgLen == 5

	case 0x14: // Extended (BEP 10)
		if msgLen <= 1 {
			return false
		}
		if len(payload) >= 6 {
			extID := payload[5]
			if extID == 0 {
				if len(payload) > 6 && payload[6] == 'd' {
					return true
				}
			} else {
				return msgLen > 2 && msgLen < 131072
			}
		}
		return msgLen > 1 && msgLen < 131072

	case 0x15, 0x16, 0x17: // Hash request, Hashes, Hash reject (BEP 52)
		return msgLen > 1 && msgLen < 131072

	default:
		return false
	}
}
