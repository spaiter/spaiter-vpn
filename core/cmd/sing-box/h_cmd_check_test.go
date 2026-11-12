package main

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func hCheckConfig(t *testing.T, content string) error {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	require.NoError(t, err)
	return checkOptions(ctx, options)
}

const hGoodOutbound = `{"type": "socks", "tag": "good", "server": "127.0.0.1", "server_port": 1080}`

func TestCheckAcceptsAValidConfig(t *testing.T) {
	t.Parallel()
	require.NoError(t, hCheckConfig(t, `{"outbounds": [`+hGoodOutbound+`]}`))
}

// box.New tolerates a broken entry beside a good one; check must not, or a
// typo in a single outbound or endpoint passes the gate and runs as a
// placeholder.
func TestCheckRejectsABrokenOutboundBesideAGoodOne(t *testing.T) {
	t.Parallel()
	for name, broken := range map[string]string{
		"unknown type":  `{"type": "no-such-type", "tag": "bad"}`,
		"unknown field": `{"type": "socks", "tag": "bad", "server": "127.0.0.1", "server_port": 1080, "unknown_field": 1}`,
	} {
		err := hCheckConfig(t, `{"outbounds": [`+hGoodOutbound+`,`+broken+`]}`)
		require.Error(t, err, name)
		require.ErrorContains(t, err, "bad", name)
	}
}

func TestCheckRejectsABrokenEndpointBesideAGoodOutbound(t *testing.T) {
	t.Parallel()
	err := hCheckConfig(t, `{"outbounds": [`+hGoodOutbound+`], "endpoints": [{"type": "no-such-endpoint", "tag": "bad-endpoint"}]}`)
	require.ErrorContains(t, err, "bad-endpoint")
}
