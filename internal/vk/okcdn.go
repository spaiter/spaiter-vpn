package vk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The OK-CDN side of the WG-over-VK pool. A call token (minted by getCallToken)
// authenticates an anonymous session against calls.okcdn.ru; a session opens a
// conversation with a join link, and holding the owner ws2 socket keeps that
// conversation alive. This is the HTTP half, reverse-engineered to match the
// desktop app and the retired vc-holder.py: two GETs, no VK OAuth.
const (
	// OKAppKey and OKCallerAppID are the VK Calls application's, fixed values
	// the okcdn API expects.
	OKAppKey      = "CDHDKPLGDIHBABABA"
	OKCallerAppID = 7793118
	// OKHost is the okcdn API; OKWSHost is where the owner socket lives.
	OKHost   = "https://calls.okcdn.ru"
	OKWSHost = "wss://videowebrtc.okcdn.ru/ws2"
	okUA     = "VK Calls/1.44.39190 (X11; linux; Linux 24.04) Boost.Beast/357"
)

// ErrCallTokenExpired is the okcdn session failing because the call token is no
// longer good. It is the signal to re-mint a call token (MintCallToken), as
// opposed to a transient error worth retrying with the same token.
var ErrCallTokenExpired = errors.New("okcdn rejected the call token")

// OKClient talks to calls.okcdn.ru. The zero value works; Host and HTTP are
// overridden in tests.
type OKClient struct {
	HTTP *http.Client
	Host string
}

func (c *OKClient) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *OKClient) host() string {
	if c.Host != "" {
		return strings.TrimRight(c.Host, "/")
	}
	return OKHost
}

func (c *OKClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", okUA)
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("reach okcdn: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read okcdn response: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode okcdn response (HTTP %d): %w", resp.StatusCode, err)
	}
	return nil
}

// Session is an anonymous okcdn login.
type Session struct {
	SessionKey string
	UID        string
}

type anonymLoginResponse struct {
	SessionKey string `json:"session_key"`
	UID        any    `json:"uid"`
	ErrorCode  int    `json:"error_code"`
	ErrorMsg   string `json:"error_msg"`
}

// AnonymLogin opens an anonymous session from a call token. A token the server
// will not accept gives ErrCallTokenExpired (an absent session key, which is
// how okcdn reports an outdated token).
func (c *OKClient) AnonymLogin(ctx context.Context, callToken string) (*Session, error) {
	if strings.TrimSpace(callToken) == "" {
		return nil, ErrCallTokenExpired
	}
	sd, err := json.Marshal(map[string]any{
		"version": 3, "client_version": 1, "auth_token": callToken, "device_id": randomHex(16),
	})
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("application_key", OKAppKey)
	q.Set("session_data", string(sd))

	var r anonymLoginResponse
	if err := c.get(ctx, "/api/auth/anonymLogin?"+q.Encode(), &r); err != nil {
		return nil, err
	}
	if r.SessionKey == "" {
		// No session key means the token is outdated (error_code 401,
		// "AUTH_LOGIN : Token is outdated") or otherwise unusable.
		return nil, fmt.Errorf("%w: %s", ErrCallTokenExpired, r.ErrorMsg)
	}
	return &Session{SessionKey: r.SessionKey, UID: toString(r.UID)}, nil
}

// Conversation is a started call: the join link clients use, plus what the
// owner socket needs to hold it open.
type Conversation struct {
	JoinLink string
	WSToken  string
	ConvID   string
}

type startConversationResponse struct {
	JoinLink string `json:"join_link"`
	Token    string `json:"token"`
	ID       any    `json:"id"`
	ErrorMsg string `json:"error_msg"`
}

// StartConversation creates a call with a join link. A response missing any of
// the three fields the owner socket needs is an error, not a half-built call.
func (c *OKClient) StartConversation(ctx context.Context, s *Session) (*Conversation, error) {
	payload, err := json.Marshal(map[string]any{
		"is_video": false, "with_join_link": true, "join_by_link": true, "caller_app_id": OKCallerAppID,
	})
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("application_key", OKAppKey)
	q.Set("session_key", s.SessionKey)
	q.Set("conversationId", randomUUID())
	q.Set("isVideo", "false")
	q.Set("protocolVersion", "6")
	q.Set("payload", string(payload))
	q.Set("createJoinLink", "true")
	q.Set("onlyAdminCanShareMovie", "false")

	var r startConversationResponse
	if err := c.get(ctx, "/api/vchat/startConversation?"+q.Encode(), &r); err != nil {
		return nil, err
	}
	if r.JoinLink == "" || r.Token == "" || toString(r.ID) == "" {
		return nil, fmt.Errorf("okcdn started no usable conversation: %s", r.ErrorMsg)
	}
	return &Conversation{JoinLink: r.JoinLink, WSToken: r.Token, ConvID: toString(r.ID)}, nil
}

// OwnerWSURL is the owner ws2 socket that keeps a conversation alive. The query
// mirrors the desktop client; peerId is random per socket.
func OwnerWSURL(wsHost string, conv *Conversation, uid string) string {
	if wsHost == "" {
		wsHost = OKWSHost
	}
	q := url.Values{}
	q.Set("appVersion", "1.44.39190")
	q.Set("capabilities", "77F")
	q.Set("clientType", "VK")
	q.Set("conversationId", conv.ConvID)
	q.Set("device", "Ubuntu 24.04.4 LTS")
	q.Set("entityType", "USER")
	q.Set("locale", "en")
	q.Set("peerId", strconv.FormatInt(randomInt63(), 10))
	q.Set("platform", "DESKTOP")
	q.Set("token", conv.WSToken)
	q.Set("userId", uid)
	q.Set("version", "5")
	return wsHost + "?" + q.Encode()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomInt63() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return 1
	}
	return n.Int64()
}
