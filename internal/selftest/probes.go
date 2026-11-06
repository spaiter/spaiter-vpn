package selftest

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Probe is one datagram sent into the test tunnel, together with what the
// sniffer is expected to make of it.
type Probe struct {
	Name string
	// Port is the destination port inside the tunnel. It is part of the
	// identity of the probe because the sniffer's log line records the
	// destination, which is how a detection is tied back to its probe.
	Port uint16
	// Detector is the expected value of `detector=` in the log line, or empty
	// for a probe that must NOT be detected.
	Detector string
	Payload  []byte
}

// Detected reports whether this probe expects a detection.
func (p Probe) Detected() bool { return p.Detector != "" }

// Probes builds the four datagrams of the test.
//
// The control packet is the entire point of the exercise. Without it, "every
// probe was rejected" is indistinguishable from "the destination was
// unreachable and nothing arrived at all" — and a negative assertion over an
// empty set is vacuously true, which is exactly how four separate checks were
// once passed while checking nothing.
func Probes() ([]Probe, error) {
	nodeID, err := randomBytes(20)
	if err != nil {
		return nil, err
	}
	target, err := randomBytes(20)
	if err != nil {
		return nil, err
	}
	infohash, err := randomBytes(20)
	if err != nil {
		return nil, err
	}
	txid, err := randomBytes(4)
	if err != nil {
		return nil, err
	}

	// BEP 5: a DHT find_node query, bencoded.
	dht := []byte("d1:ad2:id20:")
	dht = append(dht, nodeID...)
	dht = append(dht, []byte("6:target20:")...)
	dht = append(dht, target...)
	dht = append(dht, []byte("e1:q9:find_node1:t2:aa1:y1:qe")...)

	// BEP 15: the connect request. The first eight bytes are the protocol's
	// fixed magic connection id, then action 0 (connect), then a transaction
	// id the server echoes back.
	tracker := make([]byte, 16)
	binary.BigEndian.PutUint64(tracker[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(tracker[8:12], 0)
	copy(tracker[12:16], txid)

	// BEP 14: a Local Service Discovery announcement. The Host header names
	// the LSD multicast group even though the packet is addressed to the
	// tunnel, because the detector matches on the payload.
	lsd := fmt.Sprintf(
		"BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nInfohash: %s\r\nPort: 51413\r\n\r\n",
		hex.EncodeToString(infohash),
	)

	return []Probe{
		{
			Name: "control",
			Port: 5353,
			// Plain ASCII with no BitTorrent structure. If this one is ever
			// flagged, the sniffer has a false positive and the rest of the
			// run's "detected correctly" results mean nothing.
			Payload: []byte("spaiter-vpn selftest control datagram: this is not bittorrent\n"),
		},
		{Name: "dht (BEP 5)", Port: 6881, Detector: "dht", Payload: dht},
		{Name: "udp tracker connect (BEP 15)", Port: 6969, Detector: "udp-tracker-connect", Payload: tracker},
		{Name: "lsd BT-SEARCH (BEP 14)", Port: 6771, Detector: "lsd-bt-search", Payload: []byte(lsd)},
	}, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}
