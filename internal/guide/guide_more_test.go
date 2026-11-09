package guide

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// flaky is the fake source with chosen calls made to fail or answer oddly.
type flaky struct {
	fakeSource
	fail         map[string]error
	emptyLinkFor string
	directHost   string
	noCF         bool
}

func (f *flaky) Config() botcfg.Config {
	cfg := f.fakeSource.Config()
	if f.noCF {
		cfg.Subscription.HostCF = ""
	}
	cfg.Subscription.HostDirect = f.directHost
	return cfg
}
func (f *flaky) Bundle(ctx context.Context, u string, p bool) ([]byte, error) {
	if err := f.fail["Bundle"]; err != nil {
		return nil, err
	}
	return f.fakeSource.Bundle(ctx, u, p)
}
func (f *flaky) UserInbounds(ctx context.Context) ([]manage.InboundRef, error) {
	if err := f.fail["UserInbounds"]; err != nil {
		return nil, err
	}
	return f.fakeSource.UserInbounds(ctx)
}
func (f *flaky) OfferedEndpoints(ctx context.Context) ([]clientcfg.Endpoint, error) {
	if err := f.fail["OfferedEndpoints"]; err != nil {
		return nil, err
	}
	return f.fakeSource.OfferedEndpoints(ctx)
}
func (f *flaky) Link(ctx context.Context, tag, u string) (string, error) {
	if tag == f.emptyLinkFor {
		return "", nil
	}
	return f.fakeSource.Link(ctx, tag, u)
}
func (f *flaky) JSONConfig(ctx context.Context, tag, u string) ([]byte, error) {
	if err := f.fail["JSONConfig"]; err != nil {
		return nil, err
	}
	return f.fakeSource.JSONConfig(ctx, tag, u)
}
func (f *flaky) AWGConf(ctx context.Context, tag, u string) (string, error) {
	if err := f.fail["AWGConf"]; err != nil {
		return "", err
	}
	return f.fakeSource.AWGConf(ctx, tag, u)
}

type brokenSubs struct{ tokenErr, cacheErr error }

func (b brokenSubs) SubscriptionToken(string) (string, error) {
	if b.tokenErr != nil {
		return "", b.tokenErr
	}
	return "tok", nil
}
func (b brokenSubs) SetBundleCache(string, []byte) error { return b.cacheErr }

func TestABrokenMethodIsListedWithItsErrorAndTheRestStillWork(t *testing.T) {
	src := &flaky{fail: map[string]error{"JSONConfig": errors.New("json down"), "AWGConf": errors.New("awg down")}}
	g, err := Build(context.Background(), src, &fakeSubs{}, "alice", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	errs := map[string]string{}
	for _, m := range g.Methods {
		errs[m.Label] = m.Error
	}
	broken := 0
	for _, e := range errs {
		if e != "" {
			broken++
		}
	}
	// the xhttp JSON config, the TUIC link and the AWG endpoint
	if len(g.Methods) != 4 || broken != 3 {
		t.Errorf("methods=%d broken=%d: %v", len(g.Methods), broken, errs)
	}
	if html, err := Render(g); err != nil || !strings.Contains(string(html), "json down") {
		t.Errorf("render: %v", err)
	}
}

func TestAMethodWithNoLinkIsLeftOutNotShownEmpty(t *testing.T) {
	src := &flaky{emptyLinkFor: "vless-reality-in"}
	g, err := Build(context.Background(), src, nil, "alice", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range g.Methods {
		if m.Link == "" && m.File == nil && m.Error == "" {
			t.Errorf("an empty method was listed: %+v", m)
		}
	}
	if len(g.Methods) != 3 {
		t.Errorf("methods = %d, want the empty one skipped", len(g.Methods))
	}
	if len(g.Subscriptions) != 0 || g.SubscriptionQ != "" {
		t.Errorf("without a subscription registry there are no subscription links: %+v", g.Subscriptions)
	}
}

func TestEachFailureThatLeavesNothingUsableStopsTheGuide(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(0, 0)
	for name, src := range map[string]*flaky{
		"bundle":    {fail: map[string]error{"Bundle": errors.New("no bundle")}},
		"inbounds":  {fail: map[string]error{"UserInbounds": errors.New("no inbounds")}},
		"endpoints": {fail: map[string]error{"OfferedEndpoints": errors.New("no endpoints")}},
	} {
		if _, err := Build(ctx, src, &fakeSubs{}, "alice", now); err == nil {
			t.Errorf("%s: Build succeeded", name)
		}
	}
	if _, err := Build(ctx, &flaky{}, brokenSubs{tokenErr: errors.New("token store down")}, "alice", now); err == nil {
		t.Error("a failing token store did not stop the guide")
	}
	if _, err := Build(ctx, &flaky{}, brokenSubs{cacheErr: errors.New("cache read-only")}, "alice", now); err == nil {
		t.Error("a failing cache did not stop the guide")
	}
}

func TestSubscriptionLinksFollowTheConfiguredHosts(t *testing.T) {
	ctx := context.Background()
	both, err := Build(ctx, &flaky{directHost: "direct.example:10866"}, &fakeSubs{}, "alice", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(both.Subscriptions) != 2 || both.Subscriptions[1] != "http://direct.example:10866/sub/tok" {
		t.Errorf("subscriptions = %v", both.Subscriptions)
	}
	direct, _ := Build(ctx, &flaky{noCF: true, directHost: "direct.example:10866"}, &fakeSubs{}, "alice", time.Unix(0, 0))
	if len(direct.Subscriptions) != 1 || !strings.HasPrefix(direct.Subscriptions[0], "http://direct.example") || direct.SubscriptionQ == "" {
		t.Errorf("direct only: %v", direct.Subscriptions)
	}
	none, _ := Build(ctx, &flaky{noCF: true}, &fakeSubs{}, "alice", time.Unix(0, 0))
	if len(none.Subscriptions) != 0 || none.SubscriptionQ != "" {
		t.Errorf("no hosts: %v", none.Subscriptions)
	}
}

func TestHelpersFitWireGuardNamesAndFallBackToTheTag(t *testing.T) {
	if shortName("alice") != "alice" || shortName("123456789012345678") != "456789012345678" {
		t.Error("shortName must keep the last 15 characters")
	}
	if qr(strings.Repeat("x", 10000)) != "" {
		t.Error("an unencodable text got a QR")
	}
	if qr("hello") == "" {
		t.Error("a short text got no QR")
	}
	cfg := botcfg.ExampleConfig()
	if m := describe(cfg, "no-such-tag", "no-such-protocol"); m.Label != "no-such-tag" {
		t.Errorf("fallback label = %q", m.Label)
	}
}
