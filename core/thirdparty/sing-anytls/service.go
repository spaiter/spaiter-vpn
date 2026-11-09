package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"

	"github.com/spaiter/spaiter-vpn/core/thirdparty/sing-anytls/padding"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	// Swapped atomically: UpdateUsers may run while NewConnection is
	// authenticating. A plain map assignment here races with the lookup
	// below, which in Go is a hard "concurrent map read and map write"
	// crash, not just a detector warning. //H
	users           atomic.TypedValue[map[[32]byte]string]
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.UpdateUsers(config.Users)

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

// UpdateUsers replaces the user set on a running service. The new map is
// built off to the side and published in one store, so a concurrent lookup
// sees either the old set or the new one, never a half-written map. //H
func (s *Service) UpdateUsers(users []User) {
	u := make(map[[32]byte]string, len(users))
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	s.users.Store(u)
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	if user, ok := s.users.Load()[passwordSha256]; ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	session.Run()
	session.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
