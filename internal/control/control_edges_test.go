package control

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheClientNamesEachWayTheDaemonCanFail(t *testing.T) {
	ctx := context.Background()
	if _, err := (Client{Socket: filepath.Join(t.TempDir(), "absent.sock")}).Do(ctx, Request{Operation: OpStatus}); err == nil || !strings.Contains(err.Error(), "reach the control daemon") {
		t.Errorf("no daemon: %v", err)
	}

	// A daemon that answers with something that is not a Response.
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<html>not json</html>"))
	})}
	go server.Serve(listener)
	defer server.Close()
	if _, err := (Client{Socket: socket}).Do(ctx, Request{Operation: OpStatus}); err == nil || !strings.Contains(err.Error(), "decode the daemon's response (HTTP 502)") {
		t.Errorf("garbage answer: %v", err)
	}

	// An invalid context never reaches the socket.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (Client{Socket: socket}).Do(cancelled, Request{Operation: OpStatus}); err == nil {
		t.Error("a cancelled context reached the daemon")
	}
}

func TestAuditFailuresAreHandedToTheCallbackNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	var failed []error
	record := func(path string) {
		a := &Audit{Path: path, Failed: func(err error) { failed = append(failed, err) }, Now: func() time.Time { return time.Unix(1, 0) }}
		a.Record(Entry{Operation: OpStatus})
	}

	// The audit path is a directory: it cannot be opened for appending.
	asDir := filepath.Join(dir, "audit")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	record(asDir)
	// The parent cannot be created because a file is in the way.
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	record(filepath.Join(blocker, "sub", "audit.log"))
	if len(failed) != 2 {
		t.Errorf("callback saw %d failures, want 2: %v", len(failed), failed)
	}
	// Without a callback a failure is still not fatal.
	(&Audit{Path: asDir}).Record(Entry{Operation: OpStatus})
}

func TestTheDaemonRefusesToStartOverWhatIsNotItsOwnSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	regular := filepath.Join(dir, "c.sock")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Socket: regular, Backend: &fakeBackend{}}
	if err := s.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("regular file: %v", err)
	}

	// The socket's directory cannot be created.
	s = &Server{Socket: filepath.Join(regular, "sub", "c.sock"), Backend: &fakeBackend{}}
	if err := s.Serve(context.Background()); err == nil {
		t.Error("an impossible socket directory was accepted")
	}

	// A stale socket from a previous run is replaced.
	stale := filepath.Join(dir, "stale.sock")
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Socket: stale, Backend: &fakeBackend{}, Access: Access{APIVersion: APIVersion}}).Serve(ctx)
	}()
	for i := 0; i < 100; i++ {
		if conn, err := net.Dial("unix", stale); err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("stale socket: %v", err)
	}
}

func TestOnlyPostToTheV1EndpointIsAnswered(t *testing.T) {
	f := start(t, Access{APIVersion: APIVersion, Operators: []uint32{me()}})
	cases := []struct{ method, path string }{{http.MethodGet, "/v1"}, {http.MethodPost, "/v2"}, {http.MethodDelete, "/"}}
	for _, c := range cases {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", f.server.Socket)
		}}
		req := httptest.NewRequest(c.method, "http://control"+c.path, nil)
		req.RequestURI = ""
		resp, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		transport.CloseIdleConnections()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestLoadAccessRefusesAMissingFile(t *testing.T) {
	if _, err := LoadAccess(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing access file was accepted")
	}
	if got := MergeAccess(Access{Operators: []uint32{5}}, nil); len(got.Operators) != 1 {
		t.Errorf("merge with nothing managed = %+v", got)
	}
}
