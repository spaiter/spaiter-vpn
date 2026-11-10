// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package lib embeds the MasterDnsVPN client in another Go program. The program
// gives the tunnel domains, the resolvers and the key, runs the client, and opens
// TCP streams through the tunnel with Dial. No local proxy is opened and nothing
// is read from or written to disk. hiddify-sing-box uses it for its masterdns
// outbound.
// ==============================================================================
package lib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

// Log levels passed to Options.Log.
const (
	LevelDebug = logger.LevelDebug
	LevelInfo  = logger.LevelInfo
	LevelWarn  = logger.LevelWarn
	LevelError = logger.LevelError
)

// Encryption methods, the values of DATA_ENCRYPTION_METHOD.
const (
	EncryptionNone      = 0
	EncryptionXOR       = 1
	EncryptionChaCha20  = 2
	EncryptionAES128GCM = 3
	EncryptionAES192GCM = 4
	EncryptionAES256GCM = 5
)

// Errors of Dial, re-exported from the client.
var (
	ErrNotReady       = client.ErrNotReady
	ErrConnectTimeout = client.ErrConnectTimeout
)

// ConnectError is the server's answer to a connect that failed.
type ConnectError = client.ConnectError

// ClientConfig is the complete client configuration, every setting of client_config.toml.
type ClientConfig = config.ClientConfig

// Options describe a tunnel. Every other client setting keeps the default of the sample
// configuration; Tune changes them.
type Options struct {
	// Domains are the tunnel domains the server is the authority for. At least one.
	Domains []string
	// Resolvers are DNS resolvers in the client_resolvers.txt formats: "8.8.8.8", "1.1.1.1:5353",
	// "10.0.0.0/30", "10.0.0.0/30:5353" or "[2001:db8::1]:53". At least one.
	Resolvers []string
	// EncryptionMethod is one of the Encryption constants, the server's DATA_ENCRYPTION_METHOD.
	EncryptionMethod int
	// EncryptionKey is the server's key, required unless EncryptionMethod is EncryptionNone.
	EncryptionKey string
	// Mode is "socks5" (the server connects each stream to the destination given to Dial) or
	// "tcp" (the server forwards every stream to its fixed target). Empty means "socks5".
	Mode string
	// LogLevel is "debug", "info", "warn" or "error"; empty means "info".
	LogLevel string
	// Log receives every log line at or above LogLevel. Nil writes them to standard output.
	Log func(level int, message string)
	// SocketControl runs on every UDP socket to a resolver before it is bound or connected.
	SocketControl func(network, address string, rc syscall.RawConn) error
	// Tune changes any other setting of the client configuration before it is validated.
	Tune func(cfg *ClientConfig)
}

// Client is a running or runnable tunnel client.
type Client struct {
	cfg   config.ClientConfig
	log   *logger.Logger
	inner *client.Client
}

// ParseEncryptionMethod reads a method as its number or its name: none, xor, chacha20,
// aes-128-gcm, aes-192-gcm or aes-256-gcm (also written aes128gcm, aes128).
func ParseEncryptionMethod(value string) (int, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.NewReplacer("-", "", "_", "", " ", "").Replace(v)
	switch v {
	case "", "xor", "1":
		return EncryptionXOR, nil
	case "none", "off", "plain", "0":
		return EncryptionNone, nil
	case "chacha20", "chacha", "2":
		return EncryptionChaCha20, nil
	case "aes128gcm", "aes128", "3":
		return EncryptionAES128GCM, nil
	case "aes192gcm", "aes192", "4":
		return EncryptionAES192GCM, nil
	case "aes256gcm", "aes256", "aes", "5":
		return EncryptionAES256GCM, nil
	}
	return 0, fmt.Errorf("unknown encryption method %q: use none, xor, chacha20, aes-128-gcm, aes-192-gcm or aes-256-gcm", value)
}

// EncryptionMethodName returns the name of a method, as ParseEncryptionMethod reads it.
func EncryptionMethodName(method int) string {
	switch method {
	case EncryptionNone:
		return "none"
	case EncryptionXOR:
		return "xor"
	case EncryptionChaCha20:
		return "chacha20"
	case EncryptionAES128GCM:
		return "aes-128-gcm"
	case EncryptionAES192GCM:
		return "aes-192-gcm"
	case EncryptionAES256GCM:
		return "aes-256-gcm"
	}
	return fmt.Sprintf("%d", method)
}

// New validates the options and prepares a client. Run starts it.
func New(opts Options) (*Client, error) {
	cfg := config.DefaultClientConfig()
	cfg.Domains = opts.Domains
	cfg.DataEncryptionMethod = opts.EncryptionMethod
	cfg.EncryptionKey = opts.EncryptionKey
	switch strings.ToLower(strings.TrimSpace(opts.Mode)) {
	case "", "socks5", "socks":
		cfg.ProtocolType = "SOCKS5"
	case "tcp":
		cfg.ProtocolType = "TCP"
	default:
		return nil, fmt.Errorf("unknown mode %q: use socks5 or tcp", opts.Mode)
	}
	if opts.LogLevel != "" {
		cfg.LogLevel = strings.ToUpper(opts.LogLevel)
	}
	// nothing local: no proxy, no DNS server, no files
	cfg.ListenPort = 0
	cfg.LocalDNSEnabled = false
	cfg.LocalDNSCachePersist = false
	cfg.SaveMTUServersToFile = false

	if len(opts.Resolvers) == 0 {
		return nil, errors.New("at least one resolver is required")
	}
	resolvers, resolverMap, err := config.ParseResolverEntries(opts.Resolvers)
	if err != nil {
		return nil, err
	}
	cfg.Resolvers = resolvers
	cfg.ResolverMap = resolverMap

	defaults := config.DefaultClientConfig()
	if opts.Tune != nil {
		opts.Tune(&cfg)
	}
	// a worker count Tune changed is meant, like one written in a configuration file
	cfg.MarkExplicitWorkers(cfg.RX_TX_Workers != defaults.RX_TX_Workers, cfg.TunnelProcessWorkers != defaults.TunnelProcessWorkers)
	cfg, err = config.FinalizeClientConfig(cfg)
	if err != nil {
		return nil, err
	}

	log := logger.New("MasterDnsVPN", cfg.LogLevel)
	if opts.Log != nil {
		log.SetSink(opts.Log)
	}

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encryption setup: %w", err)
	}

	inner := client.New(cfg, log, codec)
	inner.SetLibraryMode(true)
	if opts.SocketControl != nil {
		inner.SetSocketControl(opts.SocketControl)
	}
	if err := inner.BuildConnectionMap(); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, log: log, inner: inner}, nil
}

// Config is the complete client configuration in use.
func (c *Client) Config() ClientConfig {
	return c.cfg
}

// Run tests the resolvers, opens the session and serves streams until ctx is done. It returns
// nil when ctx ends, and an error when the runtime cannot start. Call it once.
func (c *Client) Run(ctx context.Context) error {
	return c.inner.Run(ctx)
}

// Ready reports whether the session with the server is established, so Dial can open streams.
func (c *Client) Ready() bool {
	return c.inner.SessionReady()
}

// WaitReady blocks until Ready or until ctx is done.
func (c *Client) WaitReady(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for !c.Ready() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}

// Dial opens a stream through the tunnel to host:port and returns it once the server has
// connected (socks5 mode), or once the server accepted the stream (tcp mode, where host and port
// are ignored). connectTimeout 0 means 30 seconds. Before Ready it returns ErrNotReady.
func (c *Client) Dial(ctx context.Context, host string, port uint16, connectTimeout time.Duration) (net.Conn, error) {
	return c.inner.DialStream(ctx, host, port, connectTimeout)
}

// Resolvers returns how many domain and resolver pairs passed the tests and are in use, and how
// many there are in all.
func (c *Client) Resolvers() (active int, total int) {
	return c.inner.ActiveResolverCount(), c.inner.TotalResolverCount()
}

// MTU returns the upload and download MTU agreed with the server, 0 before the test.
func (c *Client) MTU() (upload int, download int) {
	return c.inner.SyncedMTU()
}
