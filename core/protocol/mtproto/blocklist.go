package mtproto

import (
	"net"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"
)

// allowAll is an mtglib.IPBlocklist whose Contains always reports true. mtg uses
// the allowlist inversely to a blocklist (a connection is rejected when the IP is
// NOT contained), and mtg <2.2 requires a non-nil IPAllowlist, so this provides
// an "allow every client" policy. //H
type allowAll struct{}

func (allowAll) Contains(net.IP) bool { return true }
func (allowAll) Run(time.Duration)    {}
func (allowAll) Shutdown()            {}

func newAllowAllList() mtglib.IPBlocklist { return allowAll{} }
