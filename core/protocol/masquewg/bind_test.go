package masquewg

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/stretchr/testify/require"
)

// pipeFlow is a flow whose reads come from a channel and fail once closed.
type pipeFlow struct {
	net.PacketConn
	in     chan []byte
	closed chan struct{}
}

func newPipeFlow() *pipeFlow {
	return &pipeFlow{in: make(chan []byte, 8), closed: make(chan struct{})}
}

func (p *pipeFlow) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case d := <-p.in:
		return copy(b, d), nil, nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	}
}

func (p *pipeFlow) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

func (p *pipeFlow) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}

func receive(t *testing.T, fn conn.ReceiveFunc) chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		eps := []conn.Endpoint{nil}
		_, err := fn(bufs, sizes, eps)
		result <- err
	}()
	return result
}

func TestBindWithoutFlow(t *testing.T) {
	b := newMasqueBind()
	fns, _, err := b.Open(0)
	require.NoError(t, err, "Open must not wait for a flow")
	require.True(t, errors.Is(b.Send([][]byte{{1}}, masqueEndpoint{}), errNoFlow))

	// WireGuard's BindUpdate waits for every receiver; Close must wake them.
	got := receive(t, fns[0])
	require.NoError(t, b.Close())
	select {
	case err := <-got:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("receiver not woken by Close")
	}
}

func TestBindSurvivesFlowLossAndReopen(t *testing.T) {
	b := newMasqueBind()
	fns, _, err := b.Open(0)
	require.NoError(t, err)

	first := newPipeFlow()
	b.SetConn(first)
	first.in <- []byte("one")
	require.NoError(t, <-receive(t, fns[0]))

	first.Close()
	select {
	case <-b.lost:
	case <-time.After(5 * time.Second):
		t.Fatal("a dead flow did not ask for a redial")
	}
	require.ErrorIs(t, b.Send([][]byte{{1}}, masqueEndpoint{}), errNoFlow)

	// A rebind in between, as IpcSet does.
	require.NoError(t, b.Close())
	fns, _, err = b.Open(0)
	require.NoError(t, err)

	second := newPipeFlow()
	b.SetConn(second)
	require.NoError(t, b.Send([][]byte{{1}}, masqueEndpoint{}))
	second.in <- []byte("two")
	require.NoError(t, <-receive(t, fns[0]))
	second.Close()
}
