package manage

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestMalformedInboundAndUserListsAreErrors(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	c := clientFor(t, s)
	ctx := context.Background()
	if _, err := c.Inbounds(ctx); err == nil || !strings.Contains(err.Error(), "decode inbound list") {
		t.Errorf("inbounds: %v", err)
	}
	if _, err := c.Users(ctx, "in"); err == nil || !strings.Contains(err.Error(), "decode users of in") {
		t.Errorf("users: %v", err)
	}
}

func TestEveryCallReportsAnUnreachableAPI(t *testing.T) {
	s := newStub(t, func(http.ResponseWriter, *http.Request) {})
	c := clientFor(t, s)
	s.Close()
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"Apply":     func() error { _, err := c.Apply(ctx); return err },
		"Endpoints": func() error { _, err := c.Endpoints(ctx); return err },
		"Inbounds":  func() error { _, err := c.Inbounds(ctx); return err },
		"Users":     func() error { _, err := c.Users(ctx, "in"); return err },
		"UserStats": func() error { _, err := c.UserStats(ctx); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: no error from a dead API", name)
		}
	}
}

func TestBodiesThatCannotBeEncodedNeverReachTheWire(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a request was sent: %s %s", r.Method, r.URL)
	})
	c := clientFor(t, s)
	ctx := context.Background()
	if err := c.AddUser(ctx, "in", make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal user") {
		t.Errorf("AddUser: %v", err)
	}
	if err := c.PutEndpoint(ctx, "ep", make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal endpoint") {
		t.Errorf("PutEndpoint: %v", err)
	}
}

func TestAnAddressThatIsNotAURLIsReportedBeforeSending(t *testing.T) {
	c := &Client{BaseURL: "http://bad\x7fhost", Secret: "s", HTTP: http.DefaultClient}
	if err := c.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "build GET /version") {
		t.Errorf("error = %v", err)
	}
}

func TestATruncatedResponseIsAReadError(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		// Promise more than is sent, then drop the connection.
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short"))
		w.(http.Flusher).Flush()
		hj, _, _ := w.(http.Hijacker).Hijack()
		hj.Close()
	})
	c := clientFor(t, s)
	if err := c.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Errorf("error = %v", err)
	}
}
