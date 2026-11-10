package tcp

import "testing"

// A failed handshake sets ep.h to nil and unlocks before Close changes the state, so a segment
// in that window reached handleConnecting on a still-connecting endpoint without a handshake
// and took the process down. It must return, with the endpoint unlocked.
// From Leadaxe/sing-box-lx SPEC 048.
func TestH_HandleConnectingWithoutHandshake(t *testing.T) {
	ep := &Endpoint{}
	ep.state.Store(uint32(StateSynRecv))
	ep.h = nil
	handleConnecting(ep)
	if !ep.TryLock() {
		t.Fatal("handleConnecting left the endpoint locked")
	}
	ep.mu.Unlock()
}
