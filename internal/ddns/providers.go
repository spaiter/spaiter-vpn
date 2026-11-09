package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Provider names, as the desired-state document spells them.
const (
	Cloudflare = "cloudflare"
	DuckDNS    = "duckdns"
	DynDNS2    = "dyndns2"
)

// Providers lists the supported names.
var Providers = []string{Cloudflare, DuckDNS, DynDNS2}

// Options is everything a provider may need besides the token.
type Options struct {
	Name     string
	Token    string
	Username string // dyndns2
	Server   string // dyndns2: the update service's base URL
	// BaseURL overrides the API endpoint, for tests.
	BaseURL string
	HTTP    *http.Client
}

// NewProvider builds the named provider.
func NewProvider(o Options) (Provider, error) {
	if o.Token == "" {
		return nil, fmt.Errorf("ddns: %s needs a token", o.Name)
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	switch o.Name {
	case Cloudflare:
		base := o.BaseURL
		if base == "" {
			base = "https://api.cloudflare.com/client/v4"
		}
		return &cloudflare{base: base, token: o.Token, http: client, zones: map[string]string{}}, nil
	case DuckDNS:
		base := o.BaseURL
		if base == "" {
			base = "https://www.duckdns.org"
		}
		return &duckdns{base: base, token: o.Token, http: client}, nil
	case DynDNS2:
		if o.Server == "" || o.Username == "" {
			return nil, fmt.Errorf("ddns: dyndns2 needs a server and a username")
		}
		server, err := url.Parse(o.Server)
		if err != nil || server.Scheme != "https" || server.Host == "" {
			return nil, fmt.Errorf("ddns: dyndns2 server %q must be an https URL: the password travels with every update", o.Server)
		}
		return &dyndns2{server: strings.TrimRight(o.Server, "/"), username: o.Username, password: o.Token, http: client}, nil
	default:
		return nil, fmt.Errorf("ddns: unknown provider %q; known are %s", o.Name, strings.Join(Providers, ", "))
	}
}

// --- Cloudflare -------------------------------------------------------------

// cloudflare keeps records through the v4 API with a token scoped to
// Zone:DNS:Edit. Records it writes are DNS-only: a VPN cannot sit behind
// Cloudflare's HTTP proxy, so a proxied record is switched off, not kept.
type cloudflare struct {
	base, token string
	http        *http.Client
	zones       map[string]string // host -> zone id
}

func (c *cloudflare) Refresh() time.Duration { return time.Hour }
func (c *cloudflare) SupportsIPv6() bool     { return true }

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (c *cloudflare) Update(ctx context.Context, host, kind string, ip netip.Addr) (bool, error) {
	zone, err := c.zone(ctx, host)
	if err != nil {
		return false, err
	}
	var records []cfRecord
	query := url.Values{"type": {kind}, "name": {host}}
	if err := c.call(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?"+query.Encode(), nil, &records); err != nil {
		return false, err
	}
	want := cfRecord{Type: kind, Name: host, Content: ip.String(), TTL: 60, Proxied: false}
	switch {
	case len(records) == 0:
		return true, c.call(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", want, nil)
	case len(records) > 1:
		return false, permanent("%d %s records for %s: keep one, which record clients get would be a coin toss", len(records), kind, host)
	case records[0].Content == want.Content && !records[0].Proxied:
		return false, nil
	default:
		want.TTL = records[0].TTL
		return true, c.call(ctx, http.MethodPatch, "/zones/"+zone+"/dns_records/"+records[0].ID, want, nil)
	}
}

// zone finds the zone holding host by trying its parent names, longest first.
func (c *cloudflare) zone(ctx context.Context, host string) (string, error) {
	if id, ok := c.zones[host]; ok {
		return id, nil
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID string `json:"id"`
		}
		if err := c.call(ctx, http.MethodGet, "/zones?"+url.Values{"name": {name}}.Encode(), nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			c.zones[host] = zones[0].ID
			return zones[0].ID, nil
		}
	}
	return "", permanent("no Cloudflare zone this token can see holds %s", host)
}

func (c *cloudflare) call(ctx context.Context, method, path string, body, result any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	_ = json.Unmarshal(data, &envelope)
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return permanent("Cloudflare rejected the token (%d): it needs Zone:DNS:Edit on the zone", response.StatusCode)
	}
	if response.StatusCode/100 != 2 || !envelope.Success {
		var messages []string
		for _, e := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		err := fmt.Errorf("Cloudflare %s %s: status %d %s", method, strings.SplitN(path, "?", 2)[0], response.StatusCode, strings.Join(messages, "; "))
		if response.StatusCode/100 == 4 && response.StatusCode != http.StatusTooManyRequests {
			return PermanentError{err}
		}
		return err
	}
	if result != nil {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

// --- DuckDNS ----------------------------------------------------------------

type duckdns struct {
	base, token string
	http        *http.Client
}

func (d *duckdns) Refresh() time.Duration { return 24 * time.Hour }
func (d *duckdns) SupportsIPv6() bool     { return true }

func (d *duckdns) Update(ctx context.Context, host, kind string, ip netip.Addr) (bool, error) {
	sub, ok := strings.CutSuffix(host, ".duckdns.org")
	if !ok || sub == "" || strings.Contains(sub, ".") {
		return false, permanent("%s is not a DuckDNS name like myserver.duckdns.org", host)
	}
	query := url.Values{"domains": {sub}, "token": {d.token}, "verbose": {"true"}}
	if kind == "AAAA" {
		query.Set("ipv6", ip.String())
	} else {
		query.Set("ip", ip.String())
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/update?"+query.Encode(), nil)
	if err != nil {
		return false, err
	}
	response, err := d.http.Do(request)
	if err != nil {
		// The URL carries the token; never let it reach a log.
		return false, fmt.Errorf("DuckDNS: %s", strings.ReplaceAll(err.Error(), d.token, "<token>"))
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	switch {
	case response.StatusCode != http.StatusOK:
		return false, fmt.Errorf("DuckDNS: status %d", response.StatusCode)
	case lines[0] == "KO":
		return false, permanent("DuckDNS refused the update: wrong token, or %s is not this account's", host)
	case lines[0] != "OK":
		return false, fmt.Errorf("DuckDNS: unexpected answer %.40q", lines[0])
	}
	// verbose: OK, ipv4, ipv6, UPDATED|NOCHANGE
	return len(lines) >= 4 && lines[3] == "UPDATED", nil
}

// --- dyndns2 ----------------------------------------------------------------

type dyndns2 struct {
	server, username, password string
	http                       *http.Client
}

// Day-long: the protocol's services count repeated "nochg" updates as abuse.
func (d *dyndns2) Refresh() time.Duration { return 24 * time.Hour }
func (d *dyndns2) SupportsIPv6() bool     { return false }

func (d *dyndns2) Update(ctx context.Context, host, kind string, ip netip.Addr) (bool, error) {
	if kind != "A" {
		return false, permanent("dyndns2 keeps IPv4 records only")
	}
	query := url.Values{"hostname": {host}, "myip": {ip.String()}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.server+"/nic/update?"+query.Encode(), nil)
	if err != nil {
		return false, err
	}
	request.SetBasicAuth(d.username, d.password)
	request.Header.Set("User-Agent", "spaiter-vpn-ddns/1 (+https://github.com/spaiter/spaiter-vpn)")
	response, err := d.http.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	answer := strings.Fields(strings.TrimSpace(string(data)))
	if response.StatusCode == http.StatusUnauthorized {
		return false, permanent("dyndns2: the username or password was rejected")
	}
	if len(answer) == 0 {
		return false, fmt.Errorf("dyndns2: empty answer, status %d", response.StatusCode)
	}
	switch answer[0] {
	case "good":
		return true, nil
	case "nochg":
		return false, nil
	case "badauth", "nohost", "notfqdn", "numhost", "abuse", "!donator", "badagent", "!yours":
		return false, permanent("dyndns2 refused the update: %s", answer[0])
	default: // 911, dnserr and anything unknown: try again later
		return false, fmt.Errorf("dyndns2: %s", strings.Join(answer, " "))
	}
}
