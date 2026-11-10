package device

import (
	"crypto/rand"
	"errors"
)

// quicInitialObf is the <qi sni> tag: a QUIC v1 client Initial carrying a TLS ClientHello for sni,
// built afresh for every packet (new connection IDs, random and key share), so the decoy is not
// a fixed blob a censor can fingerprint.
type quicInitialObf struct {
	sni string
}

func newQUICInitialObf(val string) (obf, error) {
	if val == "" {
		return nil, errors.New("a server name is required")
	}
	if _, err := quicInitialPackets(val, 1); err != nil {
		return nil, err
	}
	return &quicInitialObf{sni: val}, nil
}

func (o *quicInitialObf) Obfuscate(dst, src []byte) {
	packets, err := quicInitialPackets(o.sni, 1)
	if err != nil || len(packets[0]) != quicMinInitialSize {
		rand.Read(dst[:quicMinInitialSize])
		return
	}
	copy(dst, packets[0])
}

func (o *quicInitialObf) Deobfuscate(dst, src []byte) bool {
	return true
}

func (o *quicInitialObf) ObfuscatedLen(n int) int {
	return quicMinInitialSize
}

func (o *quicInitialObf) DeobfuscatedLen(n int) int {
	return 0
}
