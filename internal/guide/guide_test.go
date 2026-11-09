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

type fakeSource struct{ provisioned []string }

func (f *fakeSource) Config() botcfg.Config {
	cfg := botcfg.ExampleConfig()
	cfg.Subscription.HostCF = "sub.example"
	return cfg
}
func (f *fakeSource) UserInbounds(context.Context) ([]manage.InboundRef, error) {
	return []manage.InboundRef{{Tag: "vless-reality-in", Type: "vless"}, {Tag: "vless-xhttp-in", Type: "vless"}, {Tag: "tuic-in", Type: "tuic"}}, nil
}
func (f *fakeSource) OfferedEndpoints(context.Context) ([]clientcfg.Endpoint, error) {
	return []clientcfg.Endpoint{{Tag: "awg-in", Type: "awg"}}, nil
}
func (f *fakeSource) Link(_ context.Context, tag, uid string) (string, error) {
	f.provisioned = append(f.provisioned, tag)
	if tag == "tuic-in" {
		return "", errors.New("inbound <down>")
	}
	return "vless://uuid@host:443?x=<y>#" + uid, nil
}
func (f *fakeSource) JSONConfig(_ context.Context, tag, _ string) ([]byte, error) {
	f.provisioned = append(f.provisioned, tag)
	return []byte(`{"outbounds":[]}`), nil
}
func (f *fakeSource) AWGConf(_ context.Context, tag, _ string) (string, error) {
	f.provisioned = append(f.provisioned, tag)
	return "[Interface]\nPrivateKey = k\n", nil
}
func (f *fakeSource) Bundle(context.Context, string, bool) ([]byte, error) { return []byte(`{}`), nil }

type fakeSubs struct{ cached string }

func (f *fakeSubs) SubscriptionToken(string) (string, error) { return "tok", nil }
func (f *fakeSubs) SetBundleCache(token string, _ []byte) error {
	f.cached = token
	return nil
}

func TestAGuideHandsOutEveryMethodTheBotOffers(t *testing.T) {
	src, subs := &fakeSource{}, &fakeSubs{}
	g, err := Build(context.Background(), src, subs, "alice", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Methods) != 4 || subs.cached != "tok" || g.Subscriptions[0] != "https://sub.example/sub/tok" || g.SubscriptionQ == "" {
		t.Fatalf("guide = %+v", g)
	}
	html, err := Render(g)
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)
	for _, want := range []string{"data:image/png;base64,", "vless-xhttp-in-alice.json", "alice.conf", "Недоступно: inbound &lt;down&gt;", "x=&lt;y&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("guide lacks %q", want)
		}
	}
	if strings.Contains(page, "<down>") || strings.Contains(page, "x=<y>") {
		t.Fatal("text from the server was not escaped")
	}
}
