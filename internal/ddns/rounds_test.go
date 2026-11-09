package ddns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder is a provider that keeps IPv6 and remembers every (host, kind, ip).
type recorder struct {
	mu    sync.Mutex
	calls []string
	v6    bool
}

func (r *recorder) Update(_ context.Context, host, kind string, ip netip.Addr) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("%s %s %s", kind, host, ip))
	return true, nil
}
func (r *recorder) Refresh() time.Duration { return time.Hour }
func (r *recorder) SupportsIPv6() bool     { return r.v6 }

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func TestNewRefusesAnUnusableConfigAndFillsDefaults(t *testing.T) {
	if _, err := New(Config{Hosts: []string{"a.example.net"}}); err == nil || !strings.Contains(err.Error(), "no provider") {
		t.Fatalf("no provider: %v", err)
	}
	if _, err := New(Config{Provider: &recorder{}}); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("no host: %v", err)
	}
	// Hosts that only get A records still count as something to keep.
	u, err := New(Config{Provider: &recorder{}, IPv4Hosts: []string{"a4.example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	if u.cfg.Interval != 5*time.Minute {
		t.Errorf("interval = %v, want the 5 minute default", u.cfg.Interval)
	}
	if len(u.cfg.IPv4Sources) != 3 || len(u.cfg.IPv6Sources) != 3 {
		t.Errorf("default echo services: %v / %v", u.cfg.IPv4Sources, u.cfg.IPv6Sources)
	}
	if u.cfg.HTTP4 == nil || u.cfg.HTTP6 == nil || u.cfg.Log == nil {
		t.Errorf("clients or log not defaulted: %+v", u.cfg)
	}
	custom := 90 * time.Second
	u, _ = New(Config{Provider: &recorder{}, Hosts: []string{"a.example.net"}, Interval: custom})
	if u.cfg.Interval != custom {
		t.Errorf("an explicit interval was replaced: %v", u.cfg.Interval)
	}
}

func TestPermanentErrorKeepsItsCauseReachable(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	err := error(PermanentError{cause})
	if err.Error() != cause.Error() {
		t.Errorf("Error() = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is cannot see through PermanentError")
	}
	wrapped := fmt.Errorf("A host: %w", err)
	var p PermanentError
	if !errors.As(wrapped, &p) {
		t.Error("errors.As must find a PermanentError inside a wrapped error")
	}
}

func TestOnceKeepsAAAAOnlyForDualStackHosts(t *testing.T) {
	v4, v6 := "203.0.113.7", "2001:db8::7"
	provider := &recorder{v6: true}
	u, err := New(Config{
		Provider: provider, Hosts: []string{"vpn.example.net"}, IPv4Hosts: []string{"udp.example.net"}, IPv6: true,
		IPv4Sources: []string{echo(t, &v4)}, IPv6Sources: []string{echo(t, &v6)},
		HTTP4: http.DefaultClient, HTTP6: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	status := u.Once(context.Background())
	if !status.OK || status.IPv4 != v4 || status.IPv6 != v6 {
		t.Fatalf("status = %+v", status)
	}
	got := strings.Join(provider.seen(), "|")
	want := "A vpn.example.net 203.0.113.7|A udp.example.net 203.0.113.7|AAAA vpn.example.net 2001:db8::7"
	if got != want {
		t.Fatalf("pushed\n  %s\nwant\n  %s\n(the A-only name must never get an AAAA record)", got, want)
	}
}

func TestOnceReportsTheFamilyThatFailedAndStillServesTheOther(t *testing.T) {
	v4 := "203.0.113.7"
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", 500) }))
	defer dead.Close()
	provider := &recorder{v6: true}
	var log bytes.Buffer
	u, _ := New(Config{
		Provider: provider, Hosts: []string{"vpn.example.net"}, IPv6: true,
		IPv4Sources: []string{echo(t, &v4)}, IPv6Sources: []string{dead.URL},
		HTTP4: http.DefaultClient, HTTP6: http.DefaultClient, Log: &log,
	})
	status := u.Once(context.Background())
	if status.OK || status.Permanent || !strings.Contains(status.Error, "public IPv6 address") {
		t.Fatalf("status = %+v", status)
	}
	if got := provider.seen(); len(got) != 1 || !strings.HasPrefix(got[0], "A vpn.example.net") {
		t.Fatalf("the working family was dropped along with the broken one: %v", got)
	}
	if !strings.Contains(log.String(), "ddns: ") || !strings.Contains(log.String(), "updated A vpn.example.net") {
		t.Fatalf("log = %q", log.String())
	}

	// And with no IPv4 at all, nothing is pushed and the cause is named.
	provider2 := &recorder{}
	u2, _ := New(Config{Provider: provider2, Hosts: []string{"vpn.example.net"}, IPv4Sources: []string{dead.URL}, HTTP4: http.DefaultClient})
	if s := u2.Once(context.Background()); s.OK || !strings.Contains(s.Error, "public IPv4 address") || len(provider2.seen()) != 0 {
		t.Fatalf("status = %+v, calls = %v", s, provider2.seen())
	}
}

func TestRunRoundsUntilCancelled(t *testing.T) {
	var hits atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) >= 3 {
			cancel()
		}
		io.WriteString(w, "203.0.113.7\n")
	}))
	defer srv.Close()
	u, _ := New(Config{
		Provider: &recorder{}, Hosts: []string{"vpn.example.net"}, Interval: 5 * time.Millisecond,
		IPv4Sources: []string{srv.URL}, HTTP4: http.DefaultClient,
	})
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if hits.Load() < 3 {
		t.Fatalf("only %d rounds ran", hits.Load())
	}
}

func TestAskEchoUnderstandsTheShapesServicesUse(t *testing.T) {
	serve := func(status int, body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name, url, want, wantErr string
	}{
		{"bare address", serve(200, "203.0.113.7\n"), "203.0.113.7", ""},
		{"cloudflare trace", serve(200, "fl=29f\nh=1.1.1.1\nip=198.51.100.4\nts=1\n"), "198.51.100.4", ""},
		{"v4-mapped v6 is a v4", serve(200, "::ffff:203.0.113.9"), "203.0.113.9", ""},
		{"server error", serve(500, "203.0.113.7"), "", "status 500"},
		{"html instead of an address", serve(200, "<html>nope</html>"), "", "not an address"},
		{"empty body", serve(200, ""), "", "not an address"},
		{"malformed url", "http://[::1", "", "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, err := askEcho(ctx, http.DefaultClient, tc.url)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || ip.String() != tc.want {
				t.Fatalf("got %v, %v; want %s", ip, err, tc.want)
			}
		})
	}
}

func TestDetectAddressRefusesWhatIsNotAPublicAddressOfTheAskedFamily(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		v4           bool
		wantErr      string
	}{
		{"private v4", "10.0.0.5", true, "not a public address"},
		{"loopback", "127.0.0.1", true, "not a public address"},
		{"link local", "169.254.1.1", true, "not a public address"},
		{"v6 where v4 was asked", "2001:db8::1", true, "wrong family"},
		{"v4 where v6 was asked", "203.0.113.7", false, "wrong family"},
		{"unique local v6", "fd00::1", false, "not a public address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := tc.answer
			_, err := DetectAddress(context.Background(), http.DefaultClient, []string{echo(t, &answer)}, tc.v4)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// With nothing to ask, the answer must be an error, not a zero address that a
// caller would go on to push to a DNS provider.
func TestDetectAddressWithoutSourcesIsAnError(t *testing.T) {
	ip, err := DetectAddress(context.Background(), http.DefaultClient, nil, true)
	if err == nil {
		t.Fatalf("no sources produced %v and no error", ip)
	}
	provider := &recorder{}
	u, _ := New(Config{Provider: provider, Hosts: []string{"vpn.example.net"}, IPv4Sources: []string{}, HTTP4: http.DefaultClient})
	if s := u.Once(context.Background()); s.OK || len(provider.seen()) != 0 {
		t.Fatalf("a round without any address service pushed %v: %+v", provider.seen(), s)
	}
}

func TestNewProviderValidatesBeforeBuilding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		o       Options
		wantErr string
	}{
		{"no token", Options{Name: Cloudflare}, "needs a token"},
		{"unknown", Options{Name: "namecheap", Token: "t"}, `unknown provider "namecheap"`},
		{"dyndns2 without a server", Options{Name: DynDNS2, Token: "t", Username: "u"}, "needs a server and a username"},
		{"dyndns2 without a user", Options{Name: DynDNS2, Token: "t", Server: "https://dyn.example.net"}, "needs a server and a username"},
		{"dyndns2 over http", Options{Name: DynDNS2, Token: "t", Username: "u", Server: "http://dyn.example.net"}, "must be an https URL"},
		{"dyndns2 without a host", Options{Name: DynDNS2, Token: "t", Username: "u", Server: "https://"}, "must be an https URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProvider(tc.o); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
	for name, want := range map[string]struct {
		refresh time.Duration
		v6      bool
	}{
		Cloudflare: {time.Hour, true},
		DuckDNS:    {24 * time.Hour, true},
		DynDNS2:    {24 * time.Hour, false},
	} {
		p, err := NewProvider(Options{Name: name, Token: "t", Username: "u", Server: "https://dyn.example.net/"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Refresh() != want.refresh || p.SupportsIPv6() != want.v6 {
			t.Errorf("%s: refresh=%v v6=%v, want %v %v", name, p.Refresh(), p.SupportsIPv6(), want.refresh, want.v6)
		}
	}
}

func cfServer(t *testing.T, handler http.HandlerFunc) Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p, err := NewProvider(Options{Name: Cloudflare, Token: "tok", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCloudflareSeparatesRetryableFromPermanentFailures(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		permanent bool
	}{
		{"unauthorised", 401, `{"success":false}`, true},
		{"forbidden", 403, `{"success":false}`, true},
		{"bad request", 400, `{"success":false,"errors":[{"code":1004,"message":"bad"}]}`, true},
		{"rate limited", 429, `{"success":false}`, false},
		{"server error", 502, `bad gateway`, false},
		{"200 but not successful", 200, `{"success":false,"errors":[{"code":9109,"message":"nope"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := cfServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := p.Update(context.Background(), "vpn.example.net", "A", ip)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.As(err, new(PermanentError)); got != tc.permanent {
				t.Fatalf("permanent = %v, want %v: %v", got, tc.permanent, err)
			}
		})
	}
}

func TestCloudflareRefusesToPickBetweenDuplicateRecordsAndCachesTheZone(t *testing.T) {
	var zoneLookups int
	p := cfServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			zoneLookups++
			io.WriteString(w, `{"success":true,"result":[{"id":"z1"}]}`)
		case strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodGet:
			io.WriteString(w, `{"success":true,"result":[{"id":"a","type":"A","content":"1.1.1.1"},{"id":"b","type":"A","content":"2.2.2.2"}]}`)
		default:
			t.Errorf("unexpected %s %s: two records must not be edited", r.Method, r.URL)
		}
	})
	ip := netip.MustParseAddr("203.0.113.7")
	for i := 0; i < 2; i++ {
		_, err := p.Update(context.Background(), "vpn.example.net", "A", ip)
		var perm PermanentError
		if !errors.As(err, &perm) || !strings.Contains(err.Error(), "2 A records") {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	if zoneLookups != 1 {
		t.Fatalf("the zone was looked up %d times, want it cached after the first", zoneLookups)
	}
}

func duck(t *testing.T, handler http.HandlerFunc) Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p, err := NewProvider(Options{Name: DuckDNS, Token: "secret-token", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDuckDNSAnswersAndAddressFamilies(t *testing.T) {
	var query string
	answer, status := "OK\n203.0.113.7\n\nUPDATED", 200
	p := duck(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.WriteHeader(status)
		io.WriteString(w, answer)
	})
	ctx := context.Background()
	v4, v6 := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")

	if changed, err := p.Update(ctx, "mine.duckdns.org", "A", v4); err != nil || !changed {
		t.Fatalf("UPDATED: %v %v", changed, err)
	}
	if !strings.Contains(query, "ip=203.0.113.7") || strings.Contains(query, "ipv6=") || !strings.Contains(query, "domains=mine") {
		t.Fatalf("query = %s", query)
	}
	if _, err := p.Update(ctx, "mine.duckdns.org", "AAAA", v6); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, "ipv6=2001%3Adb8%3A%3A7") || strings.Contains(query, "ip=2001") {
		t.Fatalf("AAAA must go in ipv6=, got %s", query)
	}

	answer = "OK\n203.0.113.7\n\nNOCHANGE"
	if changed, err := p.Update(ctx, "mine.duckdns.org", "A", v4); err != nil || changed {
		t.Fatalf("NOCHANGE: %v %v", changed, err)
	}
	answer = "KO"
	if _, err := p.Update(ctx, "mine.duckdns.org", "A", v4); !errors.As(err, new(PermanentError)) {
		t.Fatalf("KO is a refusal: %v", err)
	}
	answer = "<html>maintenance</html>"
	if _, err := p.Update(ctx, "mine.duckdns.org", "A", v4); err == nil || errors.As(err, new(PermanentError)) || !strings.Contains(err.Error(), "unexpected answer") {
		t.Fatalf("garbage is transient: %v", err)
	}
	answer, status = "OK", 503
	if _, err := p.Update(ctx, "mine.duckdns.org", "A", v4); err == nil || errors.As(err, new(PermanentError)) {
		t.Fatalf("a 503 is transient: %v", err)
	}

	for _, host := range []string{"example.net", "a.b.duckdns.org", ".duckdns.org", "duckdns.org"} {
		if _, err := p.Update(ctx, host, "A", v4); !errors.As(err, new(PermanentError)) {
			t.Errorf("%q is not a DuckDNS name but was sent: %v", host, err)
		}
	}
}

// The update URL carries the token as a query parameter; a transport error
// quotes the URL, and logs are read by other people.
func TestDuckDNSNeverLetsTheTokenReachAnError(t *testing.T) {
	failing := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("Get %q: connection refused", r.URL.String())
	})
	p, _ := NewProvider(Options{Name: DuckDNS, Token: "secret-token", HTTP: &http.Client{Transport: failing}})
	_, err := p.Update(context.Background(), "mine.duckdns.org", "A", netip.MustParseAddr("203.0.113.7"))
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "secret-token") || !strings.Contains(err.Error(), "<token>") {
		t.Fatalf("token leaked into %q", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDynDNS2ClassifiesAnswers(t *testing.T) {
	var agent string
	status, answer := 200, "good 203.0.113.7"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent = r.Header.Get("User-Agent")
		w.WriteHeader(status)
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	p, err := NewProvider(Options{Name: DynDNS2, Token: "pw", Username: "me", Server: srv.URL + "/", HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, ip := context.Background(), netip.MustParseAddr("203.0.113.7")

	if _, err := p.Update(ctx, "vpn.example.net", "A", ip); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(agent, "spaiter-vpn-ddns/") {
		t.Errorf("User-Agent = %q: dyndns2 services reject clients that do not identify themselves", agent)
	}
	if _, err := p.Update(ctx, "vpn.example.net", "AAAA", netip.MustParseAddr("2001:db8::7")); !errors.As(err, new(PermanentError)) {
		t.Fatalf("AAAA on dyndns2: %v", err)
	}
	status, answer = 401, ""
	if _, err := p.Update(ctx, "vpn.example.net", "A", ip); !errors.As(err, new(PermanentError)) {
		t.Fatalf("401: %v", err)
	}
	status, answer = 200, ""
	if _, err := p.Update(ctx, "vpn.example.net", "A", ip); err == nil || errors.As(err, new(PermanentError)) || !strings.Contains(err.Error(), "empty answer") {
		t.Fatalf("empty answer is transient: %v", err)
	}
	for _, word := range []string{"badauth", "nohost", "notfqdn", "numhost", "abuse", "!donator", "badagent", "!yours"} {
		answer = word
		if _, err := p.Update(ctx, "vpn.example.net", "A", ip); !errors.As(err, new(PermanentError)) {
			t.Errorf("%s must be permanent: %v", word, err)
		}
	}
	for _, word := range []string{"911", "dnserr", "something-new"} {
		answer = word
		if _, err := p.Update(ctx, "vpn.example.net", "A", ip); err == nil || errors.As(err, new(PermanentError)) {
			t.Errorf("%s must be retried: %v", word, err)
		}
	}
}

func TestStatusFileRoundTripAndFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	want := Status{Time: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), IPv4: "203.0.113.7", Updated: []string{"A vpn -> 203.0.113.7"}, OK: true}
	if err := writeStatus(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(path)
	if err != nil || !got.Time.Equal(want.Time) || got.IPv4 != want.IPv4 || !got.OK || len(got.Updated) != 1 {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v: the status is read by an unprivileged web UI", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("a temporary file was left behind: %v", entries)
	}

	if _, err := ReadStatus(filepath.Join(dir, "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing status must stay detectable: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := ReadStatus(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("a corrupt status must name its file: %v", err)
	}

	if err := writeStatus(filepath.Join(dir, "no-such-dir", "status.json"), want); err == nil {
		t.Error("writing into a missing directory must fail")
	}
}

func TestOnceSurvivesAnUnwritableStatusFile(t *testing.T) {
	addr := "203.0.113.7"
	var log bytes.Buffer
	u, _ := New(Config{
		Provider: &recorder{}, Hosts: []string{"vpn.example.net"}, IPv4Sources: []string{echo(t, &addr)}, HTTP4: http.DefaultClient,
		StatusPath: filepath.Join(t.TempDir(), "missing", "status.json"), Log: &log,
	})
	if s := u.Once(context.Background()); !s.OK {
		t.Fatalf("a status file that cannot be written must not fail the round: %+v", s)
	}
	if !strings.Contains(log.String(), "write status") {
		t.Fatalf("the failure to write the status must be logged: %q", log.String())
	}
}
