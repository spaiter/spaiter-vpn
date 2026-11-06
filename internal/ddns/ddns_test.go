package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func echo(t *testing.T, answer *string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, *answer+"\n")
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDetectAddressNeedsAgreement(t *testing.T) {
	a, b, c := "203.0.113.7", "fl=1\nip=203.0.113.7\nts=2", "198.51.100.9"
	sources := []string{echo(t, &c), echo(t, &a), echo(t, &b)}
	ip, err := DetectAddress(context.Background(), http.DefaultClient, sources, true)
	if err != nil || ip.String() != "203.0.113.7" {
		t.Fatalf("got %v, %v; want the two that agree", ip, err)
	}

	// Two answers that disagree and no third: no address is better than a guess.
	_, err = DetectAddress(context.Background(), http.DefaultClient, sources[:1:1], true)
	if err != nil {
		t.Fatalf("a single answer should stand: %v", err)
	}
	_, err = DetectAddress(context.Background(), http.DefaultClient, []string{sources[0], sources[1]}, true)
	if err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("disagreement accepted: %v", err)
	}

	private := "192.168.1.5"
	if _, err := DetectAddress(context.Background(), http.DefaultClient, []string{echo(t, &private)}, true); err == nil {
		t.Fatal("a private address was taken as public")
	}
	v6 := "2001:db8::1"
	if _, err := DetectAddress(context.Background(), http.DefaultClient, []string{echo(t, &v6)}, true); err == nil {
		t.Fatal("an IPv6 answer was taken for IPv4")
	}
}

// fakeCloudflare is enough of the v4 API: zones by name and DNS records.
type fakeCloudflare struct {
	mu      sync.Mutex
	token   string
	zone    string // zone name; its id is "z1"
	records map[string]cfRecord
	calls   []string
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	reply := func(status int, result any) {
		w.WriteHeader(status)
		data, _ := json.Marshal(result)
		json.NewEncoder(w).Encode(map[string]any{"success": status/100 == 2, "errors": []any{}, "result": json.RawMessage(data)})
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		reply(http.StatusForbidden, nil)
		return
	}
	switch {
	case r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == f.zone {
			reply(200, []map[string]string{{"id": "z1"}})
		} else {
			reply(200, []any{})
		}
	case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodGet:
		var out []cfRecord
		for _, rec := range f.records {
			if rec.Type == r.URL.Query().Get("type") && rec.Name == r.URL.Query().Get("name") {
				out = append(out, rec)
			}
		}
		reply(200, out)
	case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodPost:
		var rec cfRecord
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = "r" + rec.Type + rec.Name
		f.records[rec.ID] = rec
		reply(200, rec)
	case strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/") && r.Method == http.MethodPatch:
		id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
		var rec cfRecord
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = id
		f.records[id] = rec
		reply(200, rec)
	default:
		reply(404, nil)
	}
}

func TestCloudflareCreatesUpdatesAndUnproxies(t *testing.T) {
	fake := &fakeCloudflare{token: "tok", zone: "example.com", records: map[string]cfRecord{
		"r1": {ID: "r1", Type: "A", Name: "vpn.example.com", Content: "198.51.100.1", TTL: 300, Proxied: true},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	p, err := NewProvider(Options{Name: Cloudflare, Token: "tok", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.7")
	ctx := context.Background()

	changed, err := p.Update(ctx, "vpn.example.com", "A", ip)
	if err != nil || !changed {
		t.Fatalf("update: %v, %v", changed, err)
	}
	if rec := fake.records["r1"]; rec.Content != "203.0.113.7" || rec.Proxied || rec.TTL != 300 {
		t.Fatalf("record = %+v; want the new address, DNS-only, TTL kept", rec)
	}
	if changed, err := p.Update(ctx, "vpn.example.com", "A", ip); err != nil || changed {
		t.Fatalf("an unchanged record was rewritten: %v, %v", changed, err)
	}
	if changed, err := p.Update(ctx, "vpn.example.com", "AAAA", netip.MustParseAddr("2001:db8::7")); err != nil || !changed {
		t.Fatalf("create AAAA: %v, %v", changed, err)
	}
	if _, err := p.Update(ctx, "vpn.other.org", "A", ip); !errors.As(err, new(PermanentError)) {
		t.Fatalf("a host outside every zone: %v", err)
	}

	bad, _ := NewProvider(Options{Name: Cloudflare, Token: "wrong", BaseURL: srv.URL})
	if _, err := bad.Update(ctx, "vpn.example.com", "A", ip); !errors.As(err, new(PermanentError)) {
		t.Fatalf("a rejected token must be permanent: %v", err)
	}
}

func TestDuckDNS(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		if r.URL.Query().Get("token") != "tok" {
			io.WriteString(w, "KO")
			return
		}
		io.WriteString(w, "OK\n203.0.113.7\n\nUPDATED")
	}))
	defer srv.Close()
	p, _ := NewProvider(Options{Name: DuckDNS, Token: "tok", BaseURL: srv.URL})
	changed, err := p.Update(context.Background(), "myvpn.duckdns.org", "A", netip.MustParseAddr("203.0.113.7"))
	if err != nil || !changed || !strings.Contains(got, "domains=myvpn") || !strings.Contains(got, "ip=203.0.113.7") {
		t.Fatalf("%v %v %s", changed, err, got)
	}
	if _, err := p.Update(context.Background(), "vpn.example.com", "A", netip.MustParseAddr("203.0.113.7")); !errors.As(err, new(PermanentError)) {
		t.Fatalf("a non-DuckDNS name: %v", err)
	}
	bad, _ := NewProvider(Options{Name: DuckDNS, Token: "nope", BaseURL: srv.URL})
	if _, err := bad.Update(context.Background(), "myvpn.duckdns.org", "A", netip.MustParseAddr("203.0.113.7")); !errors.As(err, new(PermanentError)) {
		t.Fatalf("KO must be permanent: %v", err)
	}
}

func TestDynDNS2(t *testing.T) {
	answer := "good 203.0.113.7"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if r.URL.Path != "/nic/update" || user != "me" || pass != "pw" {
			io.WriteString(w, "badauth")
			return
		}
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	p, err := NewProvider(Options{Name: DynDNS2, Token: "pw", Username: "me", Server: srv.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.7")
	if changed, err := p.Update(context.Background(), "vpn.example.net", "A", ip); err != nil || !changed {
		t.Fatalf("good: %v %v", changed, err)
	}
	answer = "nochg 203.0.113.7"
	if changed, err := p.Update(context.Background(), "vpn.example.net", "A", ip); err != nil || changed {
		t.Fatalf("nochg: %v %v", changed, err)
	}
	answer = "911"
	if _, err := p.Update(context.Background(), "vpn.example.net", "A", ip); err == nil || errors.As(err, new(PermanentError)) {
		t.Fatalf("911 is temporary: %v", err)
	}
	answer = "nohost"
	if _, err := p.Update(context.Background(), "vpn.example.net", "A", ip); !errors.As(err, new(PermanentError)) {
		t.Fatalf("nohost is permanent: %v", err)
	}
	if _, err := NewProvider(Options{Name: DynDNS2, Token: "pw", Username: "me", Server: "http://insecure.example"}); err == nil {
		t.Fatal("a plain-http server would send the password in the clear")
	}
}

// countingProvider records calls and fails on demand.
type countingProvider struct {
	calls int
	err   error
}

func (c *countingProvider) Update(context.Context, string, string, netip.Addr) (bool, error) {
	c.calls++
	return c.err == nil, c.err
}
func (c *countingProvider) Refresh() time.Duration { return time.Hour }
func (c *countingProvider) SupportsIPv6() bool     { return false }

func TestUpdaterPushesOnlyChangesAndWritesStatus(t *testing.T) {
	addr := "203.0.113.7"
	provider := &countingProvider{}
	statusPath := filepath.Join(t.TempDir(), "status.json")
	u, err := New(Config{Provider: provider, Hosts: []string{"vpn.example.com"}, IPv4Hosts: []string{"vpn4.example.com"},
		IPv4Sources: []string{echo(t, &addr)}, HTTP4: http.DefaultClient, StatusPath: statusPath})
	if err != nil {
		t.Fatal(err)
	}
	if s := u.Once(context.Background()); !s.OK || provider.calls != 2 || len(s.Updated) != 2 {
		t.Fatalf("first round: %+v, %d calls", s, provider.calls)
	}
	u.Once(context.Background())
	if provider.calls != 2 {
		t.Fatalf("an unchanged address reached the provider: %d calls", provider.calls)
	}
	addr = "203.0.113.8"
	u.Once(context.Background())
	if provider.calls != 4 {
		t.Fatalf("a changed address was not pushed: %d calls", provider.calls)
	}

	provider.err = PermanentError{errors.New("token rejected")}
	addr = "203.0.113.9"
	s := u.Once(context.Background())
	if s.OK || !s.Permanent {
		t.Fatalf("status = %+v", s)
	}
	stored, err := ReadStatus(statusPath)
	if err != nil || stored.OK || !stored.Permanent || stored.IPv4 != "203.0.113.9" {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	if _, err := New(Config{Provider: provider, Hosts: []string{"x.example.com"}, IPv6: true}); err == nil {
		t.Fatal("IPv6 accepted for a provider that cannot keep AAAA")
	}
}
