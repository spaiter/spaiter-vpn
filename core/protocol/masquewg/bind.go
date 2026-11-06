package masquewg

import (
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	E "github.com/sagernet/sing/common/exceptions"
)

// masqueBind implements amneziawg-go's conn.Bind over MASQUE CONNECT-UDP flows.
// Unlike a real UDP socket there is exactly one peer — the server's WireGuard
// listener behind the proxy — so Send ignores the endpoint and always writes to
// the current flow.
//
// The flow comes and goes underneath the device: the outbound dials it in the
// background, and redials when it dies. So the bind never waits for a flow and
// never fails because there is none: with no flow, Send reports an error that
// WireGuard retries on its own timers, and receive simply blocks.
//
// Each flow is read by its own pump goroutine rather than from inside the
// ReceiveFunc. WireGuard closes and reopens the bind (BindUpdate, Close) and
// waits for every ReceiveFunc to return; a ReceiveFunc blocked in ReadFrom could
// only be woken by a read deadline, and masque-go's Conn cannot be read again
// once a deadline has fired. A select on the pump's channel can be woken. //H
type masqueBind struct {
	mu      sync.Mutex
	flow    *masqueFlow
	done    chan struct{} // closed by Close; replaced by Open
	packets chan []byte   // filled by the current flow's pump
	lost    chan struct{} // signals the outbound to redial; capacity 1
}

// masqueFlow is one CONNECT-UDP association.
type masqueFlow struct {
	pc   net.PacketConn
	stop chan struct{}
	once sync.Once
}

var _ conn.Bind = (*masqueBind)(nil)

// pumpBufferSize bounds one datagram. QUIC datagrams cannot exceed the path's
// packet size (well under 1500), so this never truncates a WireGuard packet.
const pumpBufferSize = 2048

var pumpBuffers = sync.Pool{New: func() any { b := make([]byte, pumpBufferSize); return &b }}

var errNoFlow = E.New("masque-wg: MASQUE flow not established")

func newMasqueBind() *masqueBind {
	done := make(chan struct{})
	close(done)
	return &masqueBind{
		done:    done,
		packets: make(chan []byte, 128),
		lost:    make(chan struct{}, 1),
	}
}

// SetConn installs a newly established flow and starts reading it. The flow it
// replaces, if any, must already have been dropped.
func (b *masqueBind) SetConn(pc net.PacketConn) *masqueFlow {
	f := &masqueFlow{pc: pc, stop: make(chan struct{})}
	b.mu.Lock()
	b.flow = f
	b.mu.Unlock()
	go b.pump(f)
	return f
}

func (b *masqueBind) pump(f *masqueFlow) {
	for {
		bufp := pumpBuffers.Get().(*[]byte)
		n, _, err := f.pc.ReadFrom(*bufp)
		if err != nil {
			pumpBuffers.Put(bufp)
			b.drop(f)
			return
		}
		select {
		case b.packets <- (*bufp)[:n]:
		case <-f.stop:
			pumpBuffers.Put(bufp)
			return
		}
	}
}

// drop retires a flow. If it was the current one, the outbound is told to
// redial. The caller closes the flow's connection.
func (b *masqueBind) drop(f *masqueFlow) {
	f.once.Do(func() { close(f.stop) })
	b.mu.Lock()
	current := b.flow == f
	if current {
		b.flow = nil
	}
	b.mu.Unlock()
	if current {
		select {
		case b.lost <- struct{}{}:
		default:
		}
	}
}

func (b *masqueBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	done := make(chan struct{})
	b.mu.Lock()
	b.done = done
	b.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p := <-b.packets:
			sizes[0] = copy(packets[0], p)
			p = p[:cap(p)]
			pumpBuffers.Put(&p)
			eps[0] = masqueEndpoint{}
			return 1, nil
		case <-done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *masqueBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	f := b.flow
	b.mu.Unlock()
	if f == nil {
		return errNoFlow
	}
	for _, buf := range bufs {
		if _, err := f.pc.WriteTo(buf, masqueUDPAddr); err != nil {
			return err
		}
	}
	return nil
}

// Close wakes the ReceiveFuncs of the current Open and leaves the flow alone:
// WireGuard closes and reopens the bind on IpcSet/Up, and the flow belongs to
// the outbound, which closes it.
func (b *masqueBind) Close() error {
	b.mu.Lock()
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	b.mu.Unlock()
	return nil
}

func (b *masqueBind) SetMark(uint32) error { return nil }
func (b *masqueBind) BatchSize() int       { return 1 }

func (b *masqueBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return masqueEndpoint{}, nil
}

// masqueUDPAddr is a throwaway address; masque.Conn is a connected CONNECT-UDP
// flow and ignores the WriteTo address.
var masqueUDPAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

var _ conn.Endpoint = masqueEndpoint{}

// masqueEndpoint is the single constant peer endpoint (the server WG behind the
// proxy). WireGuard only needs it to be stable and comparable.
type masqueEndpoint struct{}

func (masqueEndpoint) ClearSrc()           {}
func (masqueEndpoint) SrcToString() string { return "" }
func (masqueEndpoint) DstToString() string { return "masque:0" }
func (masqueEndpoint) DstToBytes() []byte  { return []byte{0} }
func (masqueEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (masqueEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
