package manage

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestConnectionsDecodeUserAndInbound(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"downloadTotal":1,"connections":[
			{"id":"a","upload":10,"download":20,"start":"2026-11-14T19:12:30.27Z",
			 "metadata":{"type":"awg/wg-wdtt-in","user":"80071","host":"example.com"}},
			{"id":"b","metadata":{"type":"dns"}}]}`))
	})
	conns, err := clientFor(t, s).Connections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 2 {
		t.Fatalf("conns = %+v", conns)
	}
	if conns[0].Inbound() != "wg-wdtt-in" || conns[0].Metadata.User != "80071" || conns[0].Download != 20 || conns[0].Start.IsZero() {
		t.Errorf("first = %+v", conns[0])
	}
	// An inbound type without a tag is reported as itself.
	if conns[1].Inbound() != "dns" || conns[1].Metadata.User != "" {
		t.Errorf("second = %+v", conns[1])
	}
}

func TestUserInboundStatsPathAndOldCore(t *testing.T) {
	var query string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats/user-inbounds" {
			http.NotFound(w, r)
			return
		}
		query = r.URL.RawQuery
		w.Write([]byte(`[{"date":"2026-11-14","user":"80071","inbound":"vless-reality-in","download":5,"bulk_conns":1}]`))
	})
	rows, err := clientFor(t, s).UserInboundStats(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if query != "days=2" || len(rows) != 1 || rows[0].Inbound != "vless-reality-in" || rows[0].BulkConns != 1 {
		t.Errorf("query %q rows %+v", query, rows)
	}

	// A core without the route answers 404, which callers must be able to
	// tell from a broken API.
	old := newStub(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if _, err := clientFor(t, old).UserInboundStats(context.Background(), 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("old core: %v", err)
	}
}
