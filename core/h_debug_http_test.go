package box

import (
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// The leak profile marks what it reports as leaked for good, and gVisor's parked goroutines always
// look leaked to it: refused unless forced.
func TestH_DebugGoroutineLeakRefused(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := probe.Addr().String()
	require.NoError(t, probe.Close())

	server, err := startDebugHTTPServer(option.DebugOptions{Listen: address})
	require.NoError(t, err)
	require.NotNil(t, server)
	defer server.Close()

	response, err := http.Get("http://" + address + "/debug/pprof/goroutineleak")
	require.NoError(t, err)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	require.Equal(t, http.StatusConflict, response.StatusCode)
	require.Contains(t, string(body), "force=1")

	response, err = http.Get("http://" + address + "/debug/pprof/goroutine?debug=1")
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "the other profiles are untouched")
}
