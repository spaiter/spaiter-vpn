// Package vk signs in to a VK account with a login, a password and a
// verification code, and turns the result into the call token the WG-over-VK
// pool holder needs.
//
// The sign-in is VK's "direct auth" (OAuth password grant), not the VK ID web
// flow the desktop app drives through a browser: the whole exchange is plain
// HTTP, so an installer can own it with three questions -- login, password,
// then the code VK sends -- instead of a headless Chrome and a cookie that
// expires unattended. The one thing direct auth cannot avoid is a captcha,
// which VK raises at its own discretion; that surfaces as a typed error rather
// than something this package tries to solve.
package vk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Defaults for a VK direct-auth client. The host and version are VK's; the
// application identity is left to the caller, because which app_id yields a
// token the call API accepts is a deployment decision, not a constant.
const (
	DefaultOAuthHost = "https://oauth.vk.com"
	DefaultAPIHost   = "https://api.vk.com"
	DefaultVersion   = "5.199"
)

// Client signs in to one VK account. The zero value is not usable: AppID and
// Secret identify the application VK authenticates as, and without them VK
// refuses the password grant outright.
type Client struct {
	// HTTP is the transport. Nil uses http.DefaultClient.
	HTTP *http.Client
	// OAuthHost and APIHost default to VK's when empty, and are overridden in
	// tests. Version is the API version string.
	OAuthHost string
	APIHost   string
	Version   string
	// AppID and Secret are the application's. 2FASupported asks VK to send a
	// code rather than refuse, and DeviceID ties the session to one device so
	// VK does not treat every sign-in as new.
	AppID    string
	Secret   string
	DeviceID string
}

// Token is a signed-in session: an access token for the account, and who it
// belongs to.
type Token struct {
	Access string
	UserID string
}

// Challenge is a sign-in paused for a code. VK accepted the password but wants
// a second factor; the caller shows Hint and Via, collects the code, and hands
// both back to SubmitCode. It carries the credentials so the resubmission is
// the same grant, which is why it never leaves the process.
type Challenge struct {
	// SID is VK's validation_sid, the handle for this paused sign-in.
	SID string
	// Hint is the masked phone or account the code went to; Via is how it was
	// sent (an app, an SMS, a call), as VK named it. Both are for the prompt.
	Hint string
	Via  string

	user, pass string
}

// CaptchaError is VK demanding a captcha. It is not retryable here: solving it
// needs a human to read ImageURL and a resubmission path this package does not
// offer, so the caller reports it and lets the operator try again later.
type CaptchaError struct {
	SID      string
	ImageURL string
}

func (e *CaptchaError) Error() string {
	return "VK demanded a captcha (sid " + e.SID + "); sign in again later"
}

// ErrInvalidCredentials is a login or password VK rejected. ErrWrongCode is a
// verification code it rejected; the caller can ask for the code again without
// starting the whole sign-in over.
var (
	ErrInvalidCredentials = errors.New("VK rejected the login or password")
	ErrWrongCode          = errors.New("VK rejected the verification code")
)

// Login starts a sign-in. It returns exactly one of: a Token, when the account
// has no second factor; a Challenge, when VK wants a code; or an error, which
// is ErrInvalidCredentials for a bad password, a *CaptchaError for a captcha,
// or a transport or decode failure.
func (c *Client) Login(ctx context.Context, login, password string) (*Token, *Challenge, error) {
	return c.grant(ctx, login, password, "")
}

// SubmitCode finishes a sign-in paused by a Challenge. A code VK rejects gives
// ErrWrongCode, and the same Challenge can be retried with another code.
func (c *Client) SubmitCode(ctx context.Context, ch *Challenge, code string) (*Token, error) {
	if ch == nil {
		return nil, errors.New("no challenge to answer")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrWrongCode
	}
	token, next, err := c.grant(ctx, ch.user, ch.pass, code)
	if err != nil {
		return nil, err
	}
	if next != nil {
		// VK asked for a code again rather than accepting this one.
		return nil, ErrWrongCode
	}
	return token, nil
}

// grantResponse is the subset of VK's token response this package reads.
type grantResponse struct {
	AccessToken string `json:"access_token"`
	UserID      any    `json:"user_id"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorType        string `json:"error_type"`

	ValidationSID  string `json:"validation_sid"`
	PhoneMask      string `json:"phone_mask"`
	ValidationType string `json:"validation_type"`

	CaptchaSID string `json:"captcha_sid"`
	CaptchaImg string `json:"captcha_img"`
}

func (c *Client) grant(ctx context.Context, login, password, code string) (*Token, *Challenge, error) {
	q := url.Values{}
	q.Set("grant_type", "password")
	q.Set("client_id", c.AppID)
	q.Set("client_secret", c.Secret)
	q.Set("username", login)
	q.Set("password", password)
	q.Set("2fa_supported", "1")
	q.Set("v", c.version())
	if c.DeviceID != "" {
		q.Set("device_id", c.DeviceID)
	}
	if code != "" {
		q.Set("code", code)
	}

	endpoint := c.oauthHost() + "/token?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("reach VK: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read VK response: %w", err)
	}

	var gr grantResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return nil, nil, fmt.Errorf("decode VK response (HTTP %d): %w", resp.StatusCode, err)
	}

	switch {
	case gr.AccessToken != "":
		return &Token{Access: gr.AccessToken, UserID: toString(gr.UserID)}, nil, nil
	case gr.Error == "need_validation":
		return nil, &Challenge{
			SID:  gr.ValidationSID,
			Hint: gr.PhoneMask,
			Via:  gr.ValidationType,
			user: login,
			pass: password,
		}, nil
	case gr.Error == "need_captcha":
		return nil, nil, &CaptchaError{SID: gr.CaptchaSID, ImageURL: gr.CaptchaImg}
	case gr.Error == "invalid_client", gr.Error == "invalid_request" && code == "":
		return nil, nil, fmt.Errorf("%w: %s", ErrInvalidCredentials, gr.describe())
	case gr.Error != "":
		return nil, nil, fmt.Errorf("VK refused the sign-in: %s", gr.describe())
	default:
		return nil, nil, fmt.Errorf("VK returned no token and no error (HTTP %d)", resp.StatusCode)
	}
}

func (gr grantResponse) describe() string {
	if gr.ErrorDescription != "" {
		return gr.ErrorDescription
	}
	if gr.ErrorType != "" {
		return gr.ErrorType
	}
	return gr.Error
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) oauthHost() string {
	if c.OAuthHost != "" {
		return strings.TrimRight(c.OAuthHost, "/")
	}
	return DefaultOAuthHost
}

func (c *Client) version() string {
	if c.Version != "" {
		return c.Version
	}
	return DefaultVersion
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%.0f", x)
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}
