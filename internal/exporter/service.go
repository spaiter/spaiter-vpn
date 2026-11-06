package exporter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// serviceSuffixes maps a DNS suffix to a human name. Order matters: the first
// match wins, so the more specific entries come first — "googleusercontent.com"
// before "google.com".
//
// Copied from the Python exporter it replaces, deliberately entry for entry, so
// existing dashboards keep grouping traffic the same way.
var serviceSuffixes = []struct{ suffix, service string }{
	{"1e100.net", "Google"},
	{"googleusercontent.com", "Google Cloud"},
	{"google.com", "Google"},
	{"gstatic.com", "Google"},
	{"googleapis.com", "Google APIs"},
	{"one.one.one.one", "Cloudflare DNS"},
	{"cloudflare.com", "Cloudflare"},
	{"cloudflare.net", "Cloudflare"},
	{"cloudfront.net", "Amazon CloudFront"},
	{"amazonaws.com", "Amazon AWS"},
	{"amazon.com", "Amazon"},
	{"fastly.net", "Fastly"},
	{"facebook.com", "Meta"},
	{"fbcdn.net", "Meta"},
	{"whatsapp.net", "WhatsApp"},
	{"apple.com", "Apple"},
	{"icloud.com", "Apple iCloud"},
	{"microsoft.com", "Microsoft"},
	{"msn.com", "Microsoft"},
	{"windows.com", "Microsoft"},
	{"telegram.org", "Telegram"},
	{"tiktokcdn.com", "TikTok"},
	{"tiktokv.com", "TikTok"},
	{"netflix.com", "Netflix"},
	{"nflxvideo.net", "Netflix"},
	{"spotify.com", "Spotify"},
	{"scdn.co", "Spotify"},
}

// serviceNetworks maps an address range to a human name, for the operators
// whose reverse DNS says nothing useful.
var serviceNetworks = []struct{ cidr, service string }{
	{"149.154.160.0/20", "Telegram"},
	{"91.108.4.0/22", "Telegram"},
	{"91.108.8.0/22", "Telegram"},
	{"91.108.12.0/22", "Telegram"},
	{"91.108.16.0/22", "Telegram"},
	{"91.108.56.0/22", "Telegram"},
	{"199.232.0.0/16", "Fastly"},
	{"151.101.0.0/16", "Fastly"},
	{"185.60.216.0/22", "Meta"},
	{"157.240.0.0/16", "Meta"},
	{"31.13.64.0/18", "Meta"},
	{"2a03:2880::/32", "Meta"},
	{"142.250.0.0/15", "Google"},
	{"172.217.0.0/16", "Google"},
	{"216.58.192.0/19", "Google"},
	{"2607:f8b0::/32", "Google"},
	{"1.0.0.0/24", "Cloudflare DNS"},
	{"1.1.1.0/24", "Cloudflare DNS"},
	{"2606:4700::/32", "Cloudflare"},
}

var (
	// dashedIPInName matches a reverse-DNS name that is just an encoded
	// address, like 203-0-113-5.provider.example. Such a name says nothing
	// about a service, so it yields no label.
	dashedIPInName = regexp.MustCompile(`\b\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}\b`)
	// numericFallback guards the two-label fallback against producing
	// something like "0.113" out of an address.
	numericFallback = regexp.MustCompile(`^\d{1,3}\.\d{1,3}$`)
	asnPrefix       = regexp.MustCompile(`^AS\d+\s+`)
)

// serviceResolver turns a resource — a hostname or an address — into a service
// label, caching what it learns.
type serviceResolver struct {
	// IPInfo enables the last-resort lookup against ipinfo.io.
	//
	// Off by default, and that is a deliberate departure from the exporter
	// this replaces. The resources being looked up are the addresses this
	// server's users connected to, so enabling it sends their destinations to
	// a third party — on a machine whose purpose is to keep exactly that
	// private. The original did it unconditionally and nothing said so; the
	// evidence was labels like "1&1 Versatel GmbH", an ASN org name that can
	// only have come from there.
	//
	// Metric names and label keys are identical either way: the original
	// already falls back to the resource itself when a lookup fails, so
	// dashboards keep working and only some label values are less pretty.
	IPInfo bool
	// Timeout bounds both the reverse lookup and the HTTP one.
	Timeout time.Duration

	mu     sync.Mutex
	cache  map[string]string
	client *http.Client
}

func newServiceResolver(ipinfo bool, timeout time.Duration) *serviceResolver {
	return &serviceResolver{
		IPInfo:  ipinfo,
		Timeout: timeout,
		cache:   map[string]string{},
		client:  &http.Client{Timeout: timeout},
	}
}

// Label resolves one resource.
func (r *serviceResolver) Label(resource string) string {
	if net.ParseIP(resource) == nil {
		return serviceFromName(resource)
	}

	r.mu.Lock()
	cached, ok := r.cache[resource]
	r.mu.Unlock()
	if ok && cached != "" {
		return cached
	}

	service := serviceFromIPPrefix(resource)
	if service == "" {
		if names := r.reverseLookup(resource); len(names) > 0 {
			service = serviceFromName(names[0])
		}
	}
	if service == "" || service == resource {
		service = r.ipInfoOrg(resource)
	}
	if service == "" {
		// The original's fallback, kept: a label is always produced, so no
		// series disappears when a lookup fails.
		service = resource
	}

	r.mu.Lock()
	r.cache[resource] = service
	r.mu.Unlock()
	return service
}

func (r *serviceResolver) reverseLookup(ip string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	return names
}

func (r *serviceResolver) ipInfoOrg(ip string) string {
	if !r.IPInfo {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://ipinfo.io/%s/org", ip), nil)
	if err != nil {
		return ""
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 200))
	if err != nil {
		return ""
	}
	return asnPrefix.ReplaceAllString(strings.TrimSpace(string(body)), "")
}

func serviceFromName(name string) string {
	n := strings.ToLower(strings.TrimRight(name, "."))
	for _, entry := range serviceSuffixes {
		if n == entry.suffix || strings.HasSuffix(n, "."+entry.suffix) {
			return entry.service
		}
	}
	if dashedIPInName.MatchString(n) {
		return ""
	}
	parts := strings.Split(n, ".")
	if len(parts) >= 2 {
		fallback := strings.Join(parts[len(parts)-2:], ".")
		if numericFallback.MatchString(fallback) {
			return ""
		}
		return fallback
	}
	// Not lower-cased: the original returns the argument unchanged here.
	return name
}

func serviceFromIPPrefix(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ""
	}
	for _, entry := range serviceNetworks {
		_, network, err := net.ParseCIDR(entry.cidr)
		if err != nil {
			continue
		}
		if network.Contains(addr) {
			return entry.service
		}
	}
	return ""
}
