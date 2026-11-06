package vk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The call-token mint, reverse-engineered from the VK Calls desktop app
// (2026-11-05). The app turns a VK ID silent-auth access token into the
// okcdn call token with a single standalone request:
//
//	GET {api}/method/messages.getCallToken?env=production&v=5.203&lang=3
//	Authorization: Bearer <access_token>
//	-> {"response":{"api_base_url":"https://calls.okcdn.ru","token":"$uum..."}}
//
// The access token carries expires_in=31536000 (a year), so once it is held the
// call token can be re-minted headlessly on demand with no browser and no GUI:
// this is what lets the WG-over-VK pool heal itself without driving the app.
const (
	// CallsAPIHost is where the call API lives. The app talks to api.vk.ru
	// specifically (not api.vk.com), so that is the default.
	CallsAPIHost = "https://api.vk.ru"
	// CallsAPIVersion is the version the app sends on getCallToken.
	CallsAPIVersion = "5.203"
	// callsUserAgent mirrors the desktop app; the mint does not depend on it,
	// but matching the real client keeps the request unremarkable.
	callsUserAgent = "VK Calls/1.44.39190 (linux; x86_64) Qt/5.15.13"
)

// CallToken is the okcdn credential the pool holder needs: the token itself and
// the okcdn host it authenticates against.
type CallToken struct {
	Token      string
	APIBaseURL string
}

// ErrAccessTokenExpired is the mint failing because the access token is gone --
// expired, revoked, or wrong. It is the signal to get a fresh access token (a
// new sign-in), as opposed to a transient error worth retrying as-is.
var ErrAccessTokenExpired = errors.New("VK rejected the access token")

// callTokenResponse is the subset of getCallToken this package reads.
type callTokenResponse struct {
	Response struct {
		Token      string `json:"token"`
		APIBaseURL string `json:"api_base_url"`
	} `json:"response"`
	Error *struct {
		Code int    `json:"error_code"`
		Msg  string `json:"error_msg"`
	} `json:"error"`
}

// MintCallToken exchanges a (year-long) access token for a fresh okcdn call
// token. A rejected access token gives ErrAccessTokenExpired; anything else is
// a transport, decode, or VK error the caller can retry.
func (c *Client) MintCallToken(ctx context.Context, accessToken string) (*CallToken, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, ErrAccessTokenExpired
	}

	q := url.Values{}
	q.Set("env", "production")
	q.Set("v", c.callsVersion())
	q.Set("lang", "3")
	endpoint := c.callsHost() + "/method/messages.getCallToken?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", callsUserAgent)

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach VK: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read VK response: %w", err)
	}

	var cr callTokenResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("decode getCallToken (HTTP %d): %w", resp.StatusCode, err)
	}
	if cr.Error != nil {
		// 5 = user authorization failed; 1117 = the token is expired or
		// invalidated. Both mean "sign in again", not "retry this request".
		if cr.Error.Code == 5 || cr.Error.Code == 1117 || cr.Error.Code == 1114 {
			return nil, fmt.Errorf("%w: %s", ErrAccessTokenExpired, cr.Error.Msg)
		}
		return nil, fmt.Errorf("getCallToken failed (code %d): %s", cr.Error.Code, cr.Error.Msg)
	}
	if cr.Response.Token == "" {
		return nil, fmt.Errorf("getCallToken returned no token (HTTP %d)", resp.StatusCode)
	}
	base := cr.Response.APIBaseURL
	if base == "" {
		base = "https://calls.okcdn.ru"
	}
	return &CallToken{Token: cr.Response.Token, APIBaseURL: base}, nil
}

func (c *Client) callsHost() string {
	if c.APIHost != "" {
		return strings.TrimRight(c.APIHost, "/")
	}
	return CallsAPIHost
}

func (c *Client) callsVersion() string {
	if c.Version != "" {
		return c.Version
	}
	return CallsAPIVersion
}

// AccessToken is a silent-auth access token with the facts needed to store and
// age it: the token, who it belongs to, and how long VK said it lives.
type AccessToken struct {
	Token     string
	UserID    string
	ExpiresIn int // seconds; VK Calls silent auth returns 31536000 (a year)
}

// exchangeResponseRE pulls the access token out of the raw TLS plaintext of an
// auth.exchangeSilentAuthToken response. The app fetches the token over
// QtNetwork, so a capture of its libssl buffers holds this object verbatim; the
// response is identity-encoded (not gzip'd), so a literal match is enough. This
// is the one piece that still needs the app -- a once-a-year sign-in -- and
// keeping the parse here lets it be tested without a capture rig.
var exchangeResponseRE = regexp.MustCompile(
	`\{"response":\{"access_token":"(vk1\.a\.[A-Za-z0-9._-]+)"[^}]*?"expires_in":(\d+)[^}]*?"user_id":(\d+)`)

// ExtractAccessToken finds the silent-auth access token in a captured buffer.
// It returns the first match; a buffer with no exchange response gives a nil
// token and a non-nil error, so a caller can tell "sign-in did not complete"
// from "sign-in gave a token".
func ExtractAccessToken(capture []byte) (*AccessToken, error) {
	m := exchangeResponseRE.FindSubmatch(capture)
	if m == nil {
		return nil, errors.New("no exchangeSilentAuthToken response in the capture")
	}
	exp, err := strconv.Atoi(string(m[2]))
	if err != nil {
		return nil, fmt.Errorf("unreadable expires_in: %w", err)
	}
	return &AccessToken{
		Token:     string(m[1]),
		ExpiresIn: exp,
		UserID:    string(m[3]),
	}, nil
}
