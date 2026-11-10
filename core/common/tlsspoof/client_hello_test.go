package tlsspoof

import (
	"encoding/binary"
	"strings"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"

	"github.com/stretchr/testify/require"
)

// x25519MLKEM768 is the IANA code point for the post-quantum hybrid named
// group (0x11EC). The fake ClientHello must never carry it — its 1184-byte
// key share is the reason kernel-generated ClientHellos exceed one MSS, and
// the reason this builder has to force CurvePreferences.
const x25519MLKEM768 uint16 = 0x11EC

func TestBuildFakeClientHello_ParsesWithSNI(t *testing.T) {
	t.Parallel()
	record, err := buildFakeClientHello("example.com")
	require.NoError(t, err)

	serverName := tf.IndexTLSServerName(record)
	require.NotNil(t, serverName, "output must parse as a ClientHello")
	require.Equal(t, "example.com", serverName.ServerName)

	recordLen := binary.BigEndian.Uint16(record[3:5])
	require.Equal(t, len(record)-5, int(recordLen),
		"record length header must match on-wire record size")
	handshakeLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	require.Equal(t, len(record)-5-4, handshakeLen,
		"handshake length header must match handshake body size")
}

// TestBuildFakeClientHello_FitsOneSegment is the regression guard for the
// whole point of the rewrite: the fake must never need fragmenting on a
// standard 1500-byte path MTU. 1200 leaves ~260 bytes for IP+TCP headers and
// a generous safety margin — the X25519MLKEM768 ClientHello this replaces
// hit ~1400+.
func TestBuildFakeClientHello_FitsOneSegment(t *testing.T) {
	t.Parallel()
	for _, sni := range []string{"a.io", "example.com", strings.Repeat("a", 253)} {
		record, err := buildFakeClientHello(sni)
		require.NoError(t, err, "sni=%q", sni)
		require.Less(t, len(record), 1200, "sni=%q built %d bytes", sni, len(record))
	}
}

// TestBuildFakeClientHello_NoPostQuantumKeyShare catches regressions that
// would accidentally pull an X25519MLKEM768 key share (the reason the prior
// implementation had to fragment) back into the fake — e.g. if CurvePreferences
// stopped being respected by a future Go version.
func TestBuildFakeClientHello_NoPostQuantumKeyShare(t *testing.T) {
	t.Parallel()
	record, err := buildFakeClientHello("example.com")
	require.NoError(t, err)

	// Checked where a group id can actually appear, not anywhere in the
	// record.
	//
	// Scanning the whole record for the two bytes 0x11 0xEC was flaky by
	// construction: a ClientHello carries ~96 random bytes (the random, the
	// session id and an X25519 key share), so some adjacent pair matches the
	// needle roughly once in seven hundred runs. The failure then accuses the
	// builder of offering a post-quantum group on the strength of two random
	// bytes. Parsing supported_groups and key_share makes the assertion mean
	// what its name says.
	groups, shares := namedGroups(t, record)
	// X25519 must be found, which is what stops this from passing vacuously: a
	// walker that silently parses nothing would otherwise "prove" the absence
	// of the post-quantum group just as well as a correct one.
	require.Contains(t, groups, uint16(0x001D), "supported_groups must offer X25519 (0x001d)")
	require.Contains(t, shares, uint16(0x001D), "the key share must be X25519")
	require.NotEmpty(t, groups, "the fake must offer supported_groups")
	require.NotContains(t, groups, x25519MLKEM768,
		"supported_groups offers X25519MLKEM768 (0x%04x)", x25519MLKEM768)
	require.NotEmpty(t, shares, "the fake must carry a key share")
	require.NotContains(t, shares, x25519MLKEM768,
		"key_share carries X25519MLKEM768 (0x%04x), whose 1184-byte entry is what forces fragmentation", x25519MLKEM768)
}

// namedGroups returns the group ids offered in supported_groups and the ones
// a key share is present for.
//
// A deliberately small walker over the one message shape this package builds:
// enough to reach the two extensions that can name a group, and no more.
func namedGroups(t *testing.T, record []byte) (supported, keyShare []uint16) {
	t.Helper()
	// 5-byte record header, 4-byte handshake header, 2 version, 32 random.
	body := record[5+4+2+32:]
	read := func(n int) []byte {
		require.GreaterOrEqual(t, len(body), n, "truncated ClientHello")
		out := body[:n]
		body = body[n:]
		return out
	}
	read(int(read(1)[0]))                                     // session id
	read(int(binary.BigEndian.Uint16(read(2))))               // cipher suites
	read(int(read(1)[0]))                                     // compression methods
	extensions := read(int(binary.BigEndian.Uint16(read(2)))) // extensions block

	for len(extensions) >= 4 {
		kind := binary.BigEndian.Uint16(extensions[:2])
		size := int(binary.BigEndian.Uint16(extensions[2:4]))
		require.GreaterOrEqual(t, len(extensions)-4, size, "truncated extension 0x%04x", kind)
		data := extensions[4 : 4+size]
		extensions = extensions[4+size:]

		switch kind {
		case 10: // supported_groups
			require.GreaterOrEqual(t, len(data), 2, "empty supported_groups")
			list := data[2:]
			for len(list) >= 2 {
				supported = append(supported, binary.BigEndian.Uint16(list[:2]))
				list = list[2:]
			}
		case 51: // key_share
			require.GreaterOrEqual(t, len(data), 2, "empty key_share")
			entries := data[2:]
			for len(entries) >= 4 {
				group := binary.BigEndian.Uint16(entries[:2])
				length := int(binary.BigEndian.Uint16(entries[2:4]))
				require.GreaterOrEqual(t, len(entries)-4, length, "truncated key share for 0x%04x", group)
				keyShare = append(keyShare, group)
				entries = entries[4+length:]
			}
		}
	}
	return supported, keyShare
}

// TestBuildFakeClientHello_RandomizesPerCall ensures crypto/tls generates a
// fresh random + session_id + key_share on every call, as required to avoid
// trivial fingerprinting of the spoof.
func TestBuildFakeClientHello_RandomizesPerCall(t *testing.T) {
	t.Parallel()
	first, err := buildFakeClientHello("example.com")
	require.NoError(t, err)
	second, err := buildFakeClientHello("example.com")
	require.NoError(t, err)
	require.NotEqual(t, first, second,
		"repeated calls must produce distinct bytes (random/session_id/key_share must vary)")
}

func TestBuildFakeClientHello_RejectsEmpty(t *testing.T) {
	t.Parallel()
	_, err := buildFakeClientHello("")
	require.Error(t, err)
}
