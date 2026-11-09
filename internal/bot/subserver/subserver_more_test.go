package subserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewFallsBackToTheDefaultLogger(t *testing.T) {
	if New(&fakeStore{}, nil).log == nil {
		t.Error("no logger")
	}
}

func TestMountedHandlersShareThePortButNotTheSubscriptionRoutes(t *testing.T) {
	s := newServer(&fakeStore{bundles: map[string][]byte{"t": []byte("{}")}})
	s.Mount("/app/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "mini app") }))
	h := s.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app/index.html", nil))
	if body, _ := io.ReadAll(rec.Result().Body); string(body) != "mini app" {
		t.Errorf("mounted body = %q", body)
	}
	if get(t, h, "/sub/t").StatusCode != http.StatusOK {
		t.Error("the mount displaced the subscription route")
	}
	if s.Mount("/other/", http.NotFoundHandler()) != s {
		t.Error("Mount is not chainable")
	}
}

// brokenWriter fails on the first write, as a client that hung up would.
type brokenWriter struct {
	header http.Header
	status int
}

func (b *brokenWriter) Header() http.Header       { return b.header }
func (b *brokenWriter) WriteHeader(code int)      { b.status = code }
func (b *brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestAClientThatHangsUpMidPollIsOnlyLogged(t *testing.T) {
	s := newServer(&fakeStore{bundles: map[string][]byte{"t": []byte("{}")}})
	w := &brokenWriter{header: http.Header{}}
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sub/t", nil))
	// Nothing to assert beyond not panicking; the write error is logged.
	w = &brokenWriter{header: http.Header{}}
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
}

func TestWritesAreRefusedOnEveryRoute(t *testing.T) {
	h := newServer(&fakeStore{}).Handler()
	for _, path := range []string{"/healthz", "/sub/t", "/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("x")))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d", path, rec.Code)
		}
	}
}

func TestShutdownFallsBackToCloseWhenAPollWillNotFinish(t *testing.T) {
	// A handler that never returns holds the connection open; cancelling the
	// context must still end Run, by force once the grace period passes.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	s := newServer(&fakeStore{})
	s.Mount("/hang/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, addr) }()

	var conn net.Conn
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /hang/x HTTP/1.1\r\nHost: x\r\n\r\n")
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the hanging request never started")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not end after cancellation with a stuck request")
	}
	_ = slog.Default()
}
