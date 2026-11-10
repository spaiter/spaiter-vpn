package awg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Valid base64 32-byte keys; the UAPI wants them hex-encoded on the wire.
const (
	keyA = "UCkxoNxwQSegCQVSXMJjxMUuk/ovw6P0mXrqFUyJsDU="
	keyB = "qqH0NYV5T0JQRjD/eKClgclSE+txorVqYo8R1JnQYUY="
)

func awgPeer(key, name string, prefixes ...string) option.AwgPeerOptions {
	var allowed badoption.Listable[netip.Prefix]
	for _, prefix := range prefixes {
		allowed = append(allowed, netip.MustParsePrefix(prefix))
	}
	return option.AwgPeerOptions{PublicKey: key, Username: name, AllowedIPs: allowed}
}

func TestPeersEqualIgnoresName(t *testing.T) {
	// A rename must not provoke a UAPI write: the device never sees the name.
	a := awgPeer(keyA, "before", "10.10.0.2/32")
	b := awgPeer(keyA, "after", "10.10.0.2/32")
	assert.True(t, peersEqual(a, b))

	// But a changed allowed_ips set must.
	c := awgPeer(keyA, "before", "10.10.0.3/32")
	assert.False(t, peersEqual(a, c))

	d := awgPeer(keyA, "before", "10.10.0.2/32", "10.10.1.0/24")
	assert.False(t, peersEqual(a, d))
}

func TestGenIpcPeerOrdering(t *testing.T) {
	section, err := genIpcPeer(awgPeer(keyA, "x", "10.10.0.2/32"), nil)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimPrefix(section, "\n"), "\n")
	assert.True(t, strings.HasPrefix(lines[0], "public_key="), "peer section must open with public_key")
	assert.Contains(t, section, "allowed_ip=10.10.0.2/32")
}

// The replace_allowed_ips flag has to land between the peer's public_key and
// its allowed_ip lines. Before the key it would apply to the previous peer in
// the batch; after the ranges it would wipe the ones just programmed.
func TestChangedPeerPlacesReplaceAllowedIPs(t *testing.T) {
	section, err := genIpcPeer(awgPeer(keyA, "x", "10.10.0.5/32"), nil)
	require.NoError(t, err)
	hexKey, err := publicKeyHex(keyA)
	require.NoError(t, err)
	keyLine := "\npublic_key=" + hexKey
	emitted := keyLine + "\nreplace_allowed_ips=true" + strings.TrimPrefix(section, keyLine)

	lines := strings.Split(strings.TrimPrefix(emitted, "\n"), "\n")
	keyIdx, flagIdx, ipIdx := -1, -1, -1
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "public_key="):
			keyIdx = i
		case line == "replace_allowed_ips=true":
			flagIdx = i
		case strings.HasPrefix(line, "allowed_ip="):
			if ipIdx == -1 {
				ipIdx = i
			}
		}
	}
	require.NotEqual(t, -1, keyIdx)
	require.NotEqual(t, -1, flagIdx)
	require.NotEqual(t, -1, ipIdx)
	assert.Less(t, keyIdx, flagIdx, "replace_allowed_ips must come after public_key")
	assert.Less(t, flagIdx, ipIdx, "replace_allowed_ips must come before allowed_ip")
	// Exactly one public_key line: the key must not be duplicated by the splice.
	assert.Equal(t, 1, strings.Count(emitted, "public_key="))
}

func TestPublicKeyHex(t *testing.T) {
	hexKey, err := publicKeyHex(keyA)
	require.NoError(t, err)
	assert.Len(t, hexKey, 64, "32-byte key is 64 hex chars")

	_, err = publicKeyHex("not base64!!")
	assert.Error(t, err)
}

func TestNewPeerStateIndexesByKey(t *testing.T) {
	state := newPeerState([]option.AwgPeerOptions{
		awgPeer(keyA, "a", "10.10.0.2/32"),
		awgPeer(keyB, "b", "10.10.0.3/32"),
	})
	assert.Len(t, state.peers, 2)
	assert.Equal(t, "a", state.peers[keyA].Username)
	assert.Equal(t, "b", state.peers[keyB].Username)
}

func TestReloadPeersRejectsBadInput(t *testing.T) {
	e := &Endpoint{peerState: newPeerState(nil)}

	assert.Error(t, e.ReloadPeers("nonsense"))

	// apply passes what the endpoint registry built, and that is a POINTER
	// (adapter/endpoint.Register does `new(Options)`). Accepting only the value
	// shape makes every reload fail and silently fall back to recreating the
	// endpoint, which drops every tunnel on it.
	assert.ErrorContains(t, e.ReloadPeers(option.AwgEndpointOptions{}),
		"unexpected options type", "value shape is not what the registry produces")
	assert.ErrorContains(t, e.ReloadPeers(&option.AwgEndpointOptions{}),
		"not started", "pointer shape must get past the type check")
}
