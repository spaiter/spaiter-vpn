package manage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ErrNotFound is returned for a tag or user the core does not know. Callers
// need to tell "this inbound has no users yet" apart from "the API is broken",
// and both arrive as a non-2xx response.
var ErrNotFound = errors.New("not found")

// ErrBadRequest is returned when the core rejects the request itself (HTTP
// 400) rather than failing to serve it. For an inbound's users resource that
// is the core saying "protocol X does not support users": a core built before
// a protocol gained per-user accounts answers this for it.
var ErrBadRequest = errors.New("bad request")

// InboundRef is the shape of the inbound list: enough to decide what to do with
// one, without claiming to understand its protocol options.
type InboundRef struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

// UserStat is one row of GET /stats/users.
type UserStat struct {
	User      string `json:"user"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
	ConnCount int64  `json:"conn_count"`
	Active    int64  `json:"active"`
}

// clashAPI is the slice of the core's config this package needs. Parsed
// structurally rather than searched for: several unrelated fields are also
// called "secret", and picking the wrong one yields HTTP 400.
type clashAPI struct {
	Experimental struct {
		ClashAPI struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

// NewFromCoreConfig builds a client from the core's own config file, so the
// address and the secret cannot disagree with what the core is listening on.
//
// A controller written as ":9090" means every interface; it is dialled on
// loopback, which is where the core binds it in every deployment here.
func NewFromCoreConfig(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read core config %s: %w", path, err)
	}
	var parsed clashAPI
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse core config %s: %w", path, err)
	}
	controller := parsed.Experimental.ClashAPI.ExternalController
	if controller == "" {
		return nil, fmt.Errorf("%s has no experimental.clash_api.external_controller", path)
	}
	if strings.HasPrefix(controller, ":") {
		controller = "127.0.0.1" + controller
	}
	return New(controller, parsed.Experimental.ClashAPI.Secret)
}

// Version is a liveness probe: it answers once the API is up, which is what
// tells a restart apart from a core that is still starting.
func (c *Client) Version(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/version", nil)
	return err
}

// Inbounds lists the inbounds in the running config.
func (c *Client) Inbounds(ctx context.Context) ([]InboundRef, error) {
	raw, err := c.do(ctx, http.MethodGet, "/manage/inbounds", nil)
	if err != nil {
		return nil, err
	}
	var list []InboundRef
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode inbound list %q: %w", truncate(raw), err)
	}
	return list, nil
}

// Inbound returns one inbound verbatim.
//
// json.RawMessage, not a typed struct: protocol options are flattened into the
// same object and differ per type, so typing them here would duplicate
// core/option and then drift from it. Callers read the few fields they need.
func (c *Client) Inbound(ctx context.Context, tag string) (json.RawMessage, error) {
	return c.do(ctx, http.MethodGet, "/manage/inbounds/"+url.PathEscape(tag), nil)
}

// Users lists an inbound's users. An inbound with no user list yields an empty
// slice rather than an error: that is a normal state, not a failure.
func (c *Client) Users(ctx context.Context, tag string) ([]json.RawMessage, error) {
	raw, err := c.do(ctx, http.MethodGet, "/manage/inbounds/"+url.PathEscape(tag)+"/users", nil)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode users of %s %q: %w", tag, truncate(raw), err)
	}
	return list, nil
}

// AddUser appends a user to an inbound. As with the endpoints, this writes the
// desired state; Apply is what makes it live.
func (c *Client) AddUser(ctx context.Context, tag string, user any) error {
	body, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal user for %s: %w", tag, err)
	}
	_, err = c.do(ctx, http.MethodPost, "/manage/inbounds/"+url.PathEscape(tag)+"/users", body)
	return err
}

// DeleteUser removes a user by the name it is accounted under.
func (c *Client) DeleteUser(ctx context.Context, tag, name string) error {
	_, err := c.do(ctx, http.MethodDelete,
		"/manage/inbounds/"+url.PathEscape(tag)+"/users/"+url.PathEscape(name), nil)
	return err
}

// Endpoint returns one endpoint verbatim, peers and keys included.
func (c *Client) Endpoint(ctx context.Context, tag string) (json.RawMessage, error) {
	return c.do(ctx, http.MethodGet, "/manage/endpoints/"+url.PathEscape(tag), nil)
}

// PutEndpoint replaces an endpoint. The peer list is rewritten wholesale, so a
// caller adding one peer must send the others back unchanged -- read, append,
// put. Dropping that read drops everyone else's tunnel.
func (c *Client) PutEndpoint(ctx context.Context, tag string, endpoint any) error {
	body, err := json.Marshal(endpoint)
	if err != nil {
		return fmt.Errorf("marshal endpoint %s: %w", tag, err)
	}
	_, err = c.do(ctx, http.MethodPut, "/manage/endpoints/"+url.PathEscape(tag), body)
	return err
}

// UserStats is the per-user accounting the core keeps.
func (c *Client) UserStats(ctx context.Context) ([]UserStat, error) {
	raw, err := c.do(ctx, http.MethodGet, "/stats/users", nil)
	if err != nil {
		return nil, err
	}
	var list []UserStat
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode user stats %q: %w", truncate(raw), err)
	}
	return list, nil
}

// ResetUserStats zeroes one user's counters.
func (c *Client) ResetUserStats(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodDelete, "/stats/users/"+url.PathEscape(name), nil)
	return err
}
