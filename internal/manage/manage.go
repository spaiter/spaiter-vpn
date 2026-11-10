// Package manage is a client for the fork's configuration REST API, which is
// mounted under /manage on the clash API listener.
package manage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// Client talks to a running sing-box instance.
type Client struct {
	BaseURL string
	Secret  string
	HTTP    *http.Client
}

// New builds a client for a clash API listener address such as
// "127.0.0.1:9090".
func New(controller, secret string) (*Client, error) {
	if controller == "" {
		return nil, fmt.Errorf("no clash API address")
	}
	if secret == "" {
		return nil, fmt.Errorf("no clash API secret: the API rejects unauthenticated requests")
	}
	base := controller
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("clash API address %q does not parse: %w", controller, err)
	}
	return &Client{
		BaseURL: strings.TrimRight(base, "/"),
		Secret:  secret,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// ApplyOutcome mirrors the fork's applyOutcome. The nil-ness of the fields is
// the assertion that matters: a correct apply of a brand-new tag reports it
// under Added with Recreated and Reloaded empty, which is the proof that live
// endpoints were not torn down.
type ApplyOutcome struct {
	Reloaded  []string `json:"reloaded"`
	Recreated []string `json:"recreated"`
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
}

// ApplyResult is the full response of POST /manage/apply.
type ApplyResult struct {
	Message   string       `json:"message"`
	Inbounds  ApplyOutcome `json:"inbounds"`
	Endpoints ApplyOutcome `json:"endpoints"`
}

// AddEndpoint records a desired endpoint. It does not start anything: POST
// only writes the desired state, and Apply is what brings the listener up.
func (c *Client) AddEndpoint(ctx context.Context, endpoint option.Endpoint) error {
	body, err := singjson.MarshalContext(ctx, &endpoint)
	if err != nil {
		return fmt.Errorf("marshal endpoint: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, "/manage/endpoints", body)
	return err
}

// DeleteEndpoint removes an endpoint from the desired state. As with
// AddEndpoint, the change only takes effect on Apply.
func (c *Client) DeleteEndpoint(ctx context.Context, tag string) error {
	_, err := c.do(ctx, http.MethodDelete, "/manage/endpoints/"+url.PathEscape(tag), nil)
	return err
}

// Apply diffs the config file against what is live and applies it.
func (c *Client) Apply(ctx context.Context) (*ApplyResult, error) {
	raw, err := c.do(ctx, http.MethodPost, "/manage/apply", nil)
	if err != nil {
		return nil, err
	}
	var result ApplyResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("decode apply response %q: %w", truncate(raw), err)
	}
	return &result, nil
}

// Endpoints lists the endpoints in the desired config.
func (c *Client) Endpoints(ctx context.Context) ([]json.RawMessage, error) {
	raw, err := c.do(ctx, http.MethodGet, "/manage/endpoints", nil)
	if err != nil {
		return nil, err
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode endpoint list %q: %w", truncate(raw), err)
	}
	return list, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build %s %s: %w", method, path, err)
	}
	// The secret goes in a single-line bearer header. Pulling it out of the
	// config by structured parsing rather than by grepping for "secret" is
	// what keeps it single-line: the config holds several unrelated fields by
	// that name, and a multi-line value yields HTTP 400.
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		// Wrapped so callers can tell an absent tag from a broken API: both
		// arrive here as a non-2xx response, and only one of them is normal.
		return nil, fmt.Errorf("%s %s: %w: %s", method, path, ErrNotFound, truncate(raw))
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("%s %s: %w: %s", method, path, ErrBadRequest, truncate(raw))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(raw))
	}
	return raw, nil
}

func truncate(raw []byte) string {
	const limit = 400
	s := strings.TrimSpace(string(raw))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
