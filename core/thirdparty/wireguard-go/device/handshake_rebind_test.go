package device

import (
	"testing"
	"time"
)

// A peer without a current keypair, or with one older than RejectAfterTime, has no session to
// lose, so an early rebind is allowed; a fresh handshake forbids it.
func TestSessionStale(t *testing.T) {
	peer := &Peer{}
	if !peer.sessionStale() {
		t.Fatal("a peer without a keypair must be stale")
	}
	peer.keypairs.current = &Keypair{}
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
	if peer.sessionStale() {
		t.Fatal("a peer with a fresh handshake must not be stale")
	}
	peer.lastHandshakeNano.Store(time.Now().Add(-RejectAfterTime - time.Second).UnixNano())
	if !peer.sessionStale() {
		t.Fatal("a peer whose handshake is past RejectAfterTime must be stale")
	}
}

// Rebinds after failed handshakes are rate limited to one per RekeyAttemptTime; a closed device
// never rebinds.
func TestRebindAfterFailedHandshakeRateLimit(t *testing.T) {
	device := &Device{}
	device.closed = make(chan struct{})
	close(device.closed)
	device.state.state.Store(uint32(deviceStateClosed))
	peer := &Peer{device: device}
	peer.rebindAfterFailedHandshake("test")
	first := device.net.lastHandshakeRebind.Load()
	if first == 0 {
		t.Fatal("the first attempt must claim the rate-limit slot")
	}
	peer.rebindAfterFailedHandshake("test")
	if device.net.lastHandshakeRebind.Load() != first {
		t.Fatal("a second attempt inside RekeyAttemptTime must be ignored")
	}
	deadline := time.Now().Add(time.Second)
	for device.net.rebindPending.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if device.net.rebindPending.Load() {
		t.Fatal("the rebind goroutine must release rebindPending")
	}
}
