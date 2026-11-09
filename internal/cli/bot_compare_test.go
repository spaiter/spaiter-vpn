package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot/servicetest"
)

func TestCompareSubscriptionsReadsWithoutChangingAnything(t *testing.T) {
	fx := servicetest.New(t)
	parts := &botParts{store: fx.Store, svc: fx.Service}
	ctx := context.Background()
	var out bytes.Buffer

	if err := compareSubscriptions(ctx, &out, parts); err != nil || !strings.Contains(out.String(), "no subscriptions to compare") {
		t.Fatalf("empty: %q %v", out.String(), err)
	}

	// A user with an account and a subscription, but nothing cached yet.
	if _, err := fx.Service.Link(ctx, "vless-reality-in", "42"); err != nil {
		t.Fatal(err)
	}
	token, err := fx.Store.SubscriptionToken("42")
	if err != nil {
		t.Fatal(err)
	}
	adds, puts, deletes := fx.API.Counts()
	out.Reset()
	if err := compareSubscriptions(ctx, &out, parts); err != nil {
		t.Fatalf("no cache: %v", err)
	}
	if !strings.Contains(out.String(), "no cache to compare against") || !strings.Contains(out.String(), "0 identical, 0 differing, 1 without a cache") {
		t.Errorf("no cache:\n%s", out.String())
	}

	// The cache equals a fresh build: identical, and the exit is clean.
	built, err := fx.Service.Bundle(ctx, "42", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.Store.SetBundleCache(token, built); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := compareSubscriptions(ctx, &out, parts); err != nil || !strings.Contains(out.String(), "identical") || !strings.Contains(out.String(), "1 identical, 0 differing") {
		t.Fatalf("identical: %q %v", out.String(), err)
	}

	// A cache from an older build differs: the node that changed is named, and
	// the command fails so a script notices that subscribers would be notified.
	stale := bytes.Replace(built, []byte(`"server_port"`), []byte(`"server_port_x"`), 1)
	if bytes.Equal(stale, built) {
		stale = []byte(`{"outbounds":[{"tag":"only-this","type":"direct"}]}`)
	}
	if err := fx.Store.SetBundleCache(token, stale); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = compareSubscriptions(ctx, &out, parts)
	if err == nil || !strings.Contains(err.Error(), "would change under their owner") || !strings.Contains(out.String(), "DIFFERS") {
		t.Fatalf("differing: %q %v", out.String(), err)
	}

	// Comparing is a read: no account, endpoint or deletion happened for it.
	a2, p2, d2 := fx.API.Counts()
	if a2 != adds || p2 != puts || d2 != deletes {
		t.Errorf("the comparison changed the core: adds %d→%d puts %d→%d deletes %d→%d", adds, a2, puts, p2, deletes, d2)
	}
	cached, _, _ := fx.Store.BundleCache(token)
	if !bytes.Equal(cached, stale) {
		t.Error("the comparison overwrote the cache it was comparing")
	}
}
