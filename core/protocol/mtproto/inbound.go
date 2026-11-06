// Package mtproto integrates the github.com/9seconds/mtg Telegram MTProto proxy
// as a sing-box inbound. sing-box owns the TCP listener and hands each accepted
// connection to mtglib.Proxy.ServeConn; upstream connections to Telegram data
// centers are dialed through sing-box routing via mtgNetwork. //H
package mtproto

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/inbound"
	"github.com/spaiter/spaiter-vpn/core/common/dialer"
	"github.com/spaiter/spaiter-vpn/core/common/listener"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MTProtoInboundOptions](registry, C.TypeMTProto, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	logger   log.ContextLogger
	listener *listener.Listener
	// users are matched by their ClientHello; shared serves the legacy
	// secret and every connection no user's key opens, so a probe still gets
	// mtg's domain-fronting answer.
	users  atomic.Pointer[[]userProxy]
	shared *mtglib.Proxy
	// newProxy builds a user's proxy; ReloadUsers uses it for added users.
	newProxy func(user string, secret mtglib.Secret) (*mtglib.Proxy, error)
	reload   sync.Mutex
}

type userProxy struct {
	name   string
	secret string
	key    []byte
	proxy  *mtglib.Proxy
}

// buildUsers parses users into proxies, reusing a proxy from previous when the
// same user keeps the same secret, so their live sessions are untouched.
func buildUsers(users []option.MTProtoUser, previous []userProxy, newProxy func(string, mtglib.Secret) (*mtglib.Proxy, error)) ([]userProxy, error) {
	reuse := make(map[string]userProxy, len(previous))
	for _, user := range previous {
		reuse[user.name+"\x00"+user.secret] = user
	}
	seen := map[string]bool{}
	out := make([]userProxy, 0, len(users))
	for _, user := range users {
		if user.Name == "" || seen[user.Name] {
			closeNew(out, reuse)
			return nil, E.New("mtproto user names must be unique and non-empty")
		}
		seen[user.Name] = true
		if kept, ok := reuse[user.Name+"\x00"+user.Secret]; ok {
			out = append(out, kept)
			continue
		}
		secret, err := mtglib.ParseSecret(user.Secret)
		if err != nil {
			closeNew(out, reuse)
			return nil, E.Cause(err, "parse mtproto secret of ", user.Name)
		}
		if secret.Host == "" {
			closeNew(out, reuse)
			return nil, E.New("mtproto user ", user.Name, " needs a fake-TLS (ee) secret: only those identify their user")
		}
		proxy, err := newProxy(user.Name, secret)
		if err != nil {
			closeNew(out, reuse)
			return nil, E.Cause(err, "create mtproto proxy for ", user.Name)
		}
		out = append(out, userProxy{name: user.Name, secret: user.Secret, key: append([]byte(nil), secret.Key[:]...), proxy: proxy})
	}
	return out, nil
}

// closeNew shuts the proxies built so far that were not reused.
func closeNew(built []userProxy, reused map[string]userProxy) {
	for _, user := range built {
		if _, ok := reused[user.name+"\x00"+user.secret]; !ok {
			user.proxy.Shutdown()
		}
	}
}

// ReloadUsers implements adapter.UserReloader. Users are matched by their own
// secret, never by an index, so any edit is safe; a user whose secret changed
// or who was removed has their proxy, and with it their sessions, closed. //H
func (i *Inbound) ReloadUsers(options any) error {
	opts, ok := options.(*option.MTProtoInboundOptions)
	if !ok {
		return E.New("mtproto: unexpected options type for user reload")
	}
	if len(opts.Users) == 0 {
		return E.New("mtproto: per-user mode cannot reload to an empty user list")
	}
	i.reload.Lock()
	defer i.reload.Unlock()
	previous := *i.users.Load()
	next, err := buildUsers(opts.Users, previous, i.newProxy)
	if err != nil {
		return err
	}
	i.users.Store(&next)
	kept := make(map[*mtglib.Proxy]bool, len(next))
	for _, user := range next {
		kept[user.proxy] = true
	}
	for _, user := range previous {
		if !kept[user.proxy] {
			user.proxy.Shutdown()
		}
	}
	i.logger.Info("users reloaded: ", len(next), " total")
	return nil
}

// helloTimeout bounds how long an idle connection may hold a goroutine before
// it has sent its ClientHello.
const helloTimeout = 10 * time.Second

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MTProtoInboundOptions) (adapter.Inbound, error) {
	if options.Secret == "" && len(options.Users) == 0 {
		return nil, E.New("mtproto inbound needs a secret or users")
	}

	// Without a detour, upstream connections to Telegram DCs are routed like
	// any other connection, carrying the user and the client's address, so
	// statistics, limits, bans and route rules see them. A detour keeps the
	// direct dialer it always used.
	var outboundDialer N.Dialer
	if options.Detour != "" {
		var err error
		outboundDialer, err = dialer.NewWithOptions(dialer.Options{
			Context: ctx,
			Options: option.DialerOptions{
				Detour:               options.Detour,
				BindInterface:        options.BindInterface,
				RoutingMark:          options.RoutingMark,
				ReuseAddr:            options.ReuseAddr,
				NetNs:                options.NetNs,
				TCPFastOpen:          options.TCPFastOpen,
				TCPMultiPath:         options.TCPMultiPath,
				DisableTCPKeepAlive:  options.DisableTCPKeepAlive,
				TCPKeepAlive:         options.TCPKeepAlive,
				TCPKeepAliveInterval: options.TCPKeepAliveInterval,
			},
			RemoteIsDomain: true,
		})
		if err != nil {
			return nil, err
		}
	}

	newProxy := func(user string, secret mtglib.Secret) (*mtglib.Proxy, error) {
		return mtglib.NewProxy(mtglib.ProxyOpts{
			Secret:          secret,
			Network:         &mtgNetwork{ctx: ctx, dialer: outboundDialer, router: router, tag: tag, user: user},
			AntiReplayCache: antireplay.NewStableBloomFilter(1024*1024, 0.001),
			IPBlocklist:     ipblocklist.NewNoop(),
			IPAllowlist:     newAllowAllList(),
			EventStream:     events.NewNoopStream(),
			Logger:          newMTGLogger(logger),
			Concurrency:     uint(options.Concurrency),
		})
	}

	in := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeMTProto, tag),
		ctx:     ctx,
		logger:  logger,
	}
	in.newProxy = newProxy
	users, err := buildUsers(options.Users, nil, newProxy)
	if err != nil {
		return nil, err
	}
	in.users.Store(&users)
	var secret mtglib.Secret
	if options.Secret != "" {
		if secret, err = mtglib.ParseSecret(options.Secret); err != nil {
			return nil, E.Cause(err, "parse mtproto secret")
		}
	} else {
		// No legacy secret, but strangers still need mtg's answer: domain
		// fronting to the cover site. A random key no client holds makes this
		// proxy answer nothing else. Built from a user's secret instead, it
		// would accept that user's key anonymously, including after they had
		// been removed.
		first, err := mtglib.ParseSecret(options.Users[0].Secret)
		if err != nil {
			return nil, E.Cause(err, "parse mtproto secret")
		}
		secret = mtglib.Secret{Host: first.Host}
		if _, err := rand.Read(secret.Key[:]); err != nil {
			return nil, err
		}
	}
	if in.shared, err = newProxy("", secret); err != nil {
		return nil, E.Cause(err, "create mtproto proxy")
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: in,
	})
	return in, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return i.listener.Start()
}

func (i *Inbound) Close() error {
	for _, user := range *i.users.Load() {
		user.proxy.Shutdown()
	}
	if i.shared != nil {
		i.shared.Shutdown()
	}
	return i.listener.Close()
}

// NewConnection serves one client connection through the MTProto proxy of the
// user whose key made its ClientHello. ServeConn performs the handshake and
// relay synchronously; the listener already runs each connection in its own
// goroutine.
func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()
	proxy, name := i.shared, ""
	served := net.Conn(conn)
	if users := *i.users.Load(); len(users) > 0 {
		hello, err := readClientHello(conn, helloTimeout)
		served = &replayConn{Conn: conn, buffered: hello}
		if err == nil {
			for _, user := range users {
				if clientHelloMatches(hello, user.key) {
					proxy, name = user.proxy, user.name
					break
				}
			}
		}
	}
	if name != "" {
		i.logger.InfoContext(ctx, "inbound mtproto connection from ", metadata.Source, " as ", name)
	} else {
		i.logger.InfoContext(ctx, "inbound mtproto connection from ", metadata.Source)
	}
	proxy.ServeConn(essentialsConn{Conn: served})
}
