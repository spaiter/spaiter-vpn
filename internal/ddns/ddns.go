// Package ddns keeps a server's DNS records pointed at its current public
// address, for a server whose address changes.
//
// Clients are given a domain, never the address: a config holding the address
// stops working the first time it changes. Something then has to move the
// record whenever the address moves, and that is this package: it finds the
// public address the way the internet sees it (asking echo services, because
// a server behind NAT cannot see it on any interface), and updates the
// records through the DNS provider's API when it differs.
//
// Providers: Cloudflare (API token), DuckDNS (token) and dyndns2, the
// protocol No-IP, Dynu, many registrars and most routers speak.
package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Provider updates one record. kind is "A" or "AAAA".
type Provider interface {
	Update(ctx context.Context, host, kind string, ip netip.Addr) (changed bool, err error)
	// Refresh is how often an unchanged address is pushed again anyway, so a
	// record edited by hand is put back. Long for the update protocols that
	// treat repeated no-change updates as abuse.
	Refresh() time.Duration
	// SupportsIPv6 reports whether AAAA records can be kept.
	SupportsIPv6() bool
}

// PermanentError is a failure retrying cannot fix: a rejected token, an
// unknown zone or host. The updater keeps running, because the operator may
// fix the credential, but apply refuses to call such a deployment healthy.
type PermanentError struct{ Err error }

func (e PermanentError) Error() string { return e.Err.Error() }
func (e PermanentError) Unwrap() error { return e.Err }

func permanent(format string, args ...any) error {
	return PermanentError{fmt.Errorf(format, args...)}
}

// Config is one updater.
type Config struct {
	Provider Provider
	// Hosts get an A record, and an AAAA record when IPv6 is set.
	Hosts []string
	// IPv4Hosts get only an A record: the A-only name for the UDP methods.
	IPv4Hosts []string
	IPv6      bool
	Interval  time.Duration
	// StatusPath, when set, receives the result of every round as JSON.
	StatusPath string
	// Sources override the address echo services, for tests.
	IPv4Sources, IPv6Sources []string
	// HTTP overrides the clients used to ask them; nil forces each family.
	HTTP4, HTTP6 *http.Client
	Log          io.Writer
}

// DefaultIPv4Sources and DefaultIPv6Sources answer with the caller's address.
// Three operators, so one lying or down does not decide the record.
var (
	DefaultIPv4Sources = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://1.1.1.1/cdn-cgi/trace"}
	DefaultIPv6Sources = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://[2606:4700:4700::1111]/cdn-cgi/trace"}
)

// Status is one round's result.
type Status struct {
	Time      time.Time `json:"time"`
	IPv4      string    `json:"ipv4,omitempty"`
	IPv6      string    `json:"ipv6,omitempty"`
	Updated   []string  `json:"updated,omitempty"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	Permanent bool      `json:"permanent,omitempty"`
}

// Updater remembers what it last pushed, so an unchanged address costs one
// question to an echo service and nothing at the provider.
type Updater struct {
	cfg    Config
	pushed map[string]netip.Addr // "host/kind" -> address
	at     map[string]time.Time
}

func New(cfg Config) (*Updater, error) {
	if cfg.Provider == nil {
		return nil, errors.New("ddns: no provider")
	}
	if len(cfg.Hosts)+len(cfg.IPv4Hosts) == 0 {
		return nil, errors.New("ddns: no host to keep")
	}
	if cfg.IPv6 && !cfg.Provider.SupportsIPv6() {
		return nil, errors.New("ddns: this provider keeps IPv4 records only")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.IPv4Sources == nil {
		cfg.IPv4Sources = DefaultIPv4Sources
	}
	if cfg.IPv6Sources == nil {
		cfg.IPv6Sources = DefaultIPv6Sources
	}
	if cfg.HTTP4 == nil {
		cfg.HTTP4 = familyClient("tcp4")
	}
	if cfg.HTTP6 == nil {
		cfg.HTTP6 = familyClient("tcp6")
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	return &Updater{cfg: cfg, pushed: map[string]netip.Addr{}, at: map[string]time.Time{}}, nil
}

// familyClient asks over one address family only, so an echo service answers
// with that family's address.
func familyClient(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

// Run updates every Interval until ctx ends.
func (u *Updater) Run(ctx context.Context) {
	for {
		u.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(u.cfg.Interval):
		}
	}
}

// Once runs one round: find the addresses, push those that changed.
func (u *Updater) Once(ctx context.Context) Status {
	status := Status{Time: time.Now().UTC()}
	var problems []error
	permanentFailure := false

	v4, err := DetectAddress(ctx, u.cfg.HTTP4, u.cfg.IPv4Sources, true)
	if err != nil {
		problems = append(problems, fmt.Errorf("public IPv4 address: %w", err))
	} else {
		status.IPv4 = v4.String()
		for _, host := range append(append([]string(nil), u.cfg.Hosts...), u.cfg.IPv4Hosts...) {
			u.push(ctx, &status, &problems, &permanentFailure, host, "A", v4)
		}
	}
	if u.cfg.IPv6 {
		v6, err := DetectAddress(ctx, u.cfg.HTTP6, u.cfg.IPv6Sources, false)
		if err != nil {
			problems = append(problems, fmt.Errorf("public IPv6 address: %w", err))
		} else {
			status.IPv6 = v6.String()
			for _, host := range u.cfg.Hosts {
				u.push(ctx, &status, &problems, &permanentFailure, host, "AAAA", v6)
			}
		}
	}

	status.OK = len(problems) == 0
	if !status.OK {
		status.Error = errors.Join(problems...).Error()
		status.Permanent = permanentFailure
		fmt.Fprintf(u.cfg.Log, "ddns: %s\n", strings.ReplaceAll(status.Error, "\n", "; "))
	}
	for _, record := range status.Updated {
		fmt.Fprintf(u.cfg.Log, "ddns: updated %s\n", record)
	}
	if u.cfg.StatusPath != "" {
		if err := writeStatus(u.cfg.StatusPath, status); err != nil {
			fmt.Fprintf(u.cfg.Log, "ddns: write status: %v\n", err)
		}
	}
	return status
}

func (u *Updater) push(ctx context.Context, status *Status, problems *[]error, permanentFailure *bool, host, kind string, ip netip.Addr) {
	key := host + "/" + kind
	if u.pushed[key] == ip && time.Since(u.at[key]) < u.cfg.Provider.Refresh() {
		return
	}
	changed, err := u.cfg.Provider.Update(ctx, host, kind, ip)
	if err != nil {
		*problems = append(*problems, fmt.Errorf("%s %s: %w", kind, host, err))
		var p PermanentError
		if errors.As(err, &p) {
			*permanentFailure = true
		}
		return
	}
	u.pushed[key], u.at[key] = ip, time.Now()
	if changed {
		status.Updated = append(status.Updated, fmt.Sprintf("%s %s -> %s", kind, host, ip))
	}
}

// DetectAddress asks the echo services in turn and returns the first address
// two of them agree on, or the only one any of them gave.
func DetectAddress(ctx context.Context, client *http.Client, sources []string, v4 bool) (netip.Addr, error) {
	seen := map[netip.Addr]int{}
	var first netip.Addr
	var problems []error
	for _, source := range sources {
		ip, err := askEcho(ctx, client, source)
		if err == nil && ip.Is4() != v4 {
			err = fmt.Errorf("answered %s, the wrong family", ip)
		}
		if err == nil && (!ip.IsGlobalUnicast() || ip.IsPrivate()) {
			err = fmt.Errorf("answered %s, which is not a public address", ip)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", source, err))
			continue
		}
		seen[ip]++
		if seen[ip] == 2 {
			return ip, nil
		}
		if !first.IsValid() {
			first = ip
		}
	}
	if len(seen) == 1 {
		return first, nil
	}
	if len(seen) > 1 {
		return netip.Addr{}, fmt.Errorf("the address services disagree: %v", seen)
	}
	return netip.Addr{}, errors.Join(problems...)
}

func askEcho(ctx context.Context, client *http.Client, source string) (netip.Addr, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return netip.Addr{}, err
	}
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("status %d", response.StatusCode)
	}
	text := strings.TrimSpace(string(body))
	// Cloudflare's trace is key=value lines; the others answer the bare address.
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			text = value
			break
		}
	}
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("not an address: %.40q", text)
	}
	return ip.Unmap(), nil
}

func writeStatus(path string, status Status) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ReadStatus reads what the updater last wrote.
func ReadStatus(path string) (Status, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return Status{}, fmt.Errorf("%s: %w", path, err)
	}
	return status, nil
}
