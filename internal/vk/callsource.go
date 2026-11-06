package vk

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

// LiveCallSource is the production CallSource: it mints a call token from the
// stored access token, opens an okcdn conversation, and dials its owner socket.
// It caches the call token and re-mints it when okcdn says it is outdated, so a
// single expiry does not ripple into a relogin.
type LiveCallSource struct {
	OK          *OKClient
	Mint        *Client                                   // MintCallToken lives here
	AccessToken func(ctx context.Context) (string, error) // the one-year token, from pass
	WSHost      string

	// Dial opens the owner socket. Nil uses the real websocket dialer; tests
	// substitute a fake so the source can be exercised without a server.
	Dial func(ctx context.Context, url string) (CallConn, error)

	mu        sync.Mutex
	callToken string
}

// Open mints or reuses a call token, logs an anonymous okcdn session, starts a
// conversation and holds its owner socket. ErrAccessTokenExpired propagates (a
// relogin is needed); an outdated call token is re-minted once in place.
func (s *LiveCallSource) Open(ctx context.Context) (string, CallConn, error) {
	ct, err := s.ensureCallToken(ctx, false)
	if err != nil {
		return "", nil, err
	}

	session, err := s.OK.AnonymLogin(ctx, ct)
	if errors.Is(err, ErrCallTokenExpired) {
		// The call token went stale; mint a fresh one and try once more.
		if ct, err = s.ensureCallToken(ctx, true); err != nil {
			return "", nil, err
		}
		session, err = s.OK.AnonymLogin(ctx, ct)
	}
	if err != nil {
		return "", nil, err
	}

	conv, err := s.OK.StartConversation(ctx, session)
	if err != nil {
		return "", nil, err
	}

	conn, err := s.dial(ctx, OwnerWSURL(s.WSHost, conv, session.UID))
	if err != nil {
		return "", nil, err
	}
	return conv.JoinLink, conn, nil
}

// ensureCallToken returns a call token, minting a fresh one when there is none
// cached or force is set. A dead access token surfaces as ErrAccessTokenExpired.
func (s *LiveCallSource) ensureCallToken(ctx context.Context, force bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.callToken != "" && !force {
		return s.callToken, nil
	}
	at, err := s.AccessToken(ctx)
	if err != nil {
		return "", err
	}
	call, err := s.Mint.MintCallToken(ctx, at)
	if err != nil {
		return "", err // ErrAccessTokenExpired flows through unchanged
	}
	s.callToken = call.Token
	return s.callToken, nil
}

func (s *LiveCallSource) dial(ctx context.Context, url string) (CallConn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, url)
	}
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"User-Agent": {okUA}},
	})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(-1) // join signalling frames can be large
	return &wsCallConn{conn: conn}, nil
}

// wsCallConn holds one owner socket open, answering the app-level ping with
// pong. The okcdn signalling ping is a text frame, not a protocol ping, so it
// is handled here rather than by the library's automatic pong.
type wsCallConn struct {
	conn *websocket.Conn
}

func (c *wsCallConn) Hold(ctx context.Context) error {
	for {
		typ, data, err := c.conn.Read(ctx)
		if err != nil {
			return err
		}
		if typ == websocket.MessageText && string(data) == "ping" {
			if err := c.conn.Write(ctx, websocket.MessageText, []byte("pong")); err != nil {
				return err
			}
		}
	}
}

func (c *wsCallConn) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "")
}
