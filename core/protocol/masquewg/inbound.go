// Package masquewg implements a self-hosted MASQUE (CONNECT-UDP, RFC 9298) proxy
// whose associations are locked to a single UDP target (our WireGuard listener),
// plus a matching client that runs WireGuard over the CONNECT-UDP tunnel. //H
package masquewg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/masque-go"
	qgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

const defaultWGTarget = "127.0.0.1:10863"
const defaultPath = "/m"

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MASQUEWGInboundOptions](registry, C.TypeMASQUEWG, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	target    string
	path      string
	template  *uritemplate.Template
	proxy     *masque.Proxy
	server    *http3.Server
	quicLn    *qgo.EarlyListener
	closeOnce sync.Once
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEWGInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("masque-wg: TLS is required")
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	target := options.Target
	if target == "" {
		target = defaultWGTarget
	}
	path := options.Path
	if path == "" {
		path = defaultPath
	}
	sni := options.TLS.ServerName
	if sni == "" {
		return nil, E.New("masque-wg: tls.server_name is required (used in the CONNECT-UDP URI template)")
	}
	tmpl := uritemplate.MustNew(fmt.Sprintf("https://%s:%d%s?h={target_host}&p={target_port}",
		sni, options.ListenPort, path))
	in := &Inbound{
		Adapter:   inbound.NewAdapter(C.TypeMASQUEWG, tag),
		ctx:       ctx,
		logger:    logger,
		tlsConfig: tlsConfig,
		target:    target,
		path:      path,
		template:  tmpl,
		proxy:     &masque.Proxy{},
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkUDP},
		Listen:            options.ListenOptions,
		ConnectionHandler: nil,
	})
	return in, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(h.Close) // closed with the box
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.tlsConfig.Start(); err != nil {
		return E.Cause(err, "masque-wg: start tls")
	}
	stdCfg, err := stdConfig(h.tlsConfig)
	if err != nil {
		return err
	}
	stdCfg = stdCfg.Clone()
	stdCfg.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return E.Cause(err, "masque-wg: listen udp")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(h.path, h.handle)
	h.server = &http3.Server{Handler: mux, EnableDatagrams: true}

	// Keep every QUIC packet small (<=1200, the QUIC minimum) and never probe the
	// path upward: clients reach this over mobile/DS-Lite links whose MTU is often
	// ~1280, so larger packets (default up to 1452 via DPLPMTUD) get silently
	// dropped and the CONNECT-UDP response never arrives. 1200-byte packets fit any
	// conformant path.
	ln, err := qgo.ListenEarly(packetConn, http3.ConfigureTLSConfig(stdCfg), &qgo.Config{
		EnableDatagrams:         true,
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: true,
	})
	if err != nil {
		return E.Cause(err, "masque-wg: quic listen")
	}
	h.quicLn = ln
	go h.acceptLoop()
	h.logger.Info("masque-wg CONNECT-UDP server started, forwarding to ", h.target)
	return nil
}

func (h *Inbound) acceptLoop() {
	for {
		conn, err := h.quicLn.Accept(h.ctx)
		if err != nil {
			return
		}
		go h.server.ServeQUICConn(conn)
	}
}

func (h *Inbound) handle(w http.ResponseWriter, r *http.Request) {
	mreq, perr := masque.ParseProxyRequest(r, h.template)
	if perr != nil {
		var pe *masque.ProxyRequestParseError
		if errors.As(perr, &pe) {
			w.WriteHeader(pe.HTTPStatus)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}
	// Lock the association to our fixed WG target regardless of what the client
	// requested (anti-abuse: never a general-purpose open UDP proxy).
	udpAddr, err := net.ResolveUDPAddr("udp", h.target)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	_ = mreq.Target // ignored on purpose
	if err := h.proxy.ProxyConnectedSocket(w, mreq, conn); err != nil {
		conn.Close()
	}
}

func (h *Inbound) Close() error {
	var err error
	h.closeOnce.Do(func() {
		if h.quicLn != nil {
			err = h.quicLn.Close()
		}
		if h.server != nil {
			h.server.Close()
		}
		if h.proxy != nil {
			h.proxy.Close()
		}
		// quic-go does not close a packet conn it was handed, so the port
		// stayed bound and a reloaded inbound could not listen on it again.
		if h.listener != nil {
			err = E.Errors(err, h.listener.Close())
		}
	})
	return err
}

// stdConfig extracts the crypto/tls.Config from a sing-box server TLS config.
func stdConfig(cfg tls.ServerConfig) (*tls.STDConfig, error) {
	sc, ok := cfg.(interface {
		STDConfig() (*tls.STDConfig, error)
	})
	if !ok {
		return nil, E.New("masque-wg: standard TLS required (real certificate; reality/acme-only not supported)")
	}
	return sc.STDConfig()
}
