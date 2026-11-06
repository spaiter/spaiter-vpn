// Package goose is a thin public wrapper over the GooseRelayVPN v1.7.x carrier,
// re-exposing the API that hiddify-sing-box's gooserelay outbound expects.
//
// Upstream v1.7.x moved the client into internal/carrier (unimportable from
// outside the module); this package lives inside the module so it can import
// internal/* and re-export a stable surface: New/Config/FrontingConfig/Client
// with Run/Diagnose/Shutdown/Dial. Dial wraps a carrier session as a net.Conn
// via internal/socks.NewVirtualConn.
package goose

import (
	"context"
	"net"

	"github.com/spaiter/spaiter-vpn/core/thirdparty/gooserelay/internal/carrier"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/gooserelay/internal/socks"
)

// FrontingConfig configures domain fronting (GoogleIP "ip:443", SNIHosts).
type FrontingConfig = carrier.FrontingConfig

// Config mirrors the subset of carrier.Config the outbound needs.
type Config struct {
	ScriptURLs  []string
	Fronting    FrontingConfig
	AESKeyHex   string
	DebugTiming bool
}

// Client wraps *carrier.Client with a net.Conn-oriented Dial.
type Client struct {
	c *carrier.Client
}

// New constructs a carrier client.
func New(cfg Config) (*Client, error) {
	c, err := carrier.New(carrier.Config{
		ScriptURLs:  cfg.ScriptURLs,
		Fronting:    cfg.Fronting,
		AESKeyHex:   cfg.AESKeyHex,
		DebugTiming: cfg.DebugTiming,
	})
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Run drives the long-poll loop until ctx is canceled.
func (c *Client) Run(ctx context.Context) error { return c.c.Run(ctx) }

// Diagnose runs a one-shot end-to-end reachability/key probe.
func (c *Client) Diagnose(ctx context.Context) error { return c.c.Diagnose(ctx) }

// Shutdown best-effort RSTs active sessions.
func (c *Client) Shutdown(ctx context.Context) { c.c.Shutdown(ctx) }

// Dial opens a tunneled session to target ("host:port") and returns it as a
// net.Conn (reads from the session RxChan, writes via EnqueueInitialData/Tx).
func (c *Client) Dial(target string) net.Conn {
	return socks.NewVirtualConn(c.c.NewSession(target))
}
