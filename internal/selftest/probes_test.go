package selftest

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestProbesShape(t *testing.T) {
	probes, err := Probes()
	if err != nil {
		t.Fatalf("Probes: %v", err)
	}
	if len(probes) != 4 {
		t.Fatalf("got %d probes, want 4", len(probes))
	}

	byName := map[string]Probe{}
	ports := map[uint16]string{}
	detectors := map[string]string{}
	controls := 0
	for _, p := range probes {
		byName[p.Name] = p
		if other, dup := ports[p.Port]; dup {
			t.Errorf("port %d used by both %q and %q; detections are tied to probes by destination port, so they must differ", p.Port, other, p.Name)
		}
		ports[p.Port] = p.Name
		if p.Detected() {
			if other, dup := detectors[p.Detector]; dup {
				t.Errorf("detector %q expected for both %q and %q", p.Detector, other, p.Name)
			}
			detectors[p.Detector] = p.Name
		} else {
			controls++
		}
		if len(p.Payload) == 0 {
			t.Errorf("probe %q has no payload", p.Name)
		}
	}
	if controls != 1 {
		t.Errorf("there are %d control probes, want exactly 1; without one, \"everything was rejected\" could just mean nothing arrived", controls)
	}

	control := byName["control"]
	// The control must be free of every structure the detectors key on, or it
	// is not a control.
	for _, marker := range [][]byte{
		[]byte("BT-SEARCH"),
		[]byte("d1:ad2:id20:"),
		[]byte("Host: 239.192.152.143:6771"),
		[]byte("BitTorrent protocol"),
	} {
		if bytes.Contains(control.Payload, marker) {
			t.Errorf("the control payload contains %q, so a detection on it would be correct rather than a false positive", marker)
		}
	}

	dht := byName["dht (BEP 5)"]
	if !bytes.HasPrefix(dht.Payload, []byte("d1:ad2:id20:")) {
		t.Errorf("DHT payload does not start with a bencoded dictionary: %q", dht.Payload[:min(20, len(dht.Payload))])
	}
	if !bytes.Contains(dht.Payload, []byte("1:q9:find_node")) {
		t.Error("DHT payload is not a find_node query")
	}
	if dht.Port != 6881 {
		t.Errorf("DHT probe targets port %d, want 6881", dht.Port)
	}

	tracker := byName["udp tracker connect (BEP 15)"]
	if len(tracker.Payload) != 16 {
		t.Fatalf("tracker connect request is %d bytes, want 16", len(tracker.Payload))
	}
	if magic := binary.BigEndian.Uint64(tracker.Payload[0:8]); magic != 0x41727101980 {
		t.Errorf("tracker magic connection id is %#x, want 0x41727101980", magic)
	}
	if action := binary.BigEndian.Uint32(tracker.Payload[8:12]); action != 0 {
		t.Errorf("tracker action is %d, want 0 (connect)", action)
	}

	lsd := byName["lsd BT-SEARCH (BEP 14)"]
	if !bytes.HasPrefix(lsd.Payload, []byte("BT-SEARCH * HTTP/1.1\r\n")) {
		t.Errorf("LSD payload does not open with the BT-SEARCH request line: %q", lsd.Payload)
	}
	if !bytes.HasSuffix(lsd.Payload, []byte("\r\n\r\n")) {
		t.Error("LSD payload is not terminated by a blank line, so it is not a complete HTTP-style message")
	}
}

func TestProbePayloadsAreFreshEachRun(t *testing.T) {
	// The infohash, node id and transaction id are random so that two runs are
	// not byte-identical; a fixed payload would be indistinguishable from a
	// replayed one in the log.
	a, err := Probes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Probes()
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if !a[i].Detected() {
			continue
		}
		if bytes.Equal(a[i].Payload, b[i].Payload) {
			t.Errorf("probe %q produced an identical payload twice", a[i].Name)
		}
	}
}
