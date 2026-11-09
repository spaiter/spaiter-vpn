package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	mu        sync.Mutex
	commits   int
	commitErr error
}

func (f *fakeBackend) Status(context.Context) (any, error) {
	return map[string]string{"state": "ok", "secret": "s3cr3t-value-123"}, nil
}
func (f *fakeBackend) Generations(context.Context) (any, error) { return []int{1, 2}, nil }
func (f *fakeBackend) Preflight(_ context.Context, out io.Writer) (any, error) {
	fmt.Fprintln(out, "preflight ok")
	return nil, nil
}
func (f *fakeBackend) Prepare(_ context.Context, change Change, out io.Writer) (Prepared, error) {
	fmt.Fprintln(out, "planned with s3cr3t-value-123")
	return Prepared{
		Plan: map[string]string{"mode": "migrate"},
		Commit: func(context.Context, io.Writer) (any, string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.commits++
			return map[string]int{"generation": 3}, "tx-3", f.commitErr
		},
	}, nil
}
func (f *fakeBackend) SelfTest(context.Context, io.Writer) error { return nil }
func (f *fakeBackend) Redact(text string) string {
	return strings.ReplaceAll(text, "s3cr3t-value-123", "[redacted]")
}

type fixture struct {
	server  *Server
	client  Client
	backend *fakeBackend
	audit   string
	now     time.Time
}

func start(t *testing.T, access Access) *fixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fixture{backend: &fakeBackend{}, audit: filepath.Join(dir, "audit.log"), now: time.Unix(1000, 0)}
	f.server = &Server{
		Socket: filepath.Join(dir, "c.sock"), Access: access, Backend: f.backend,
		Audit: &Audit{Path: f.audit}, Now: func() time.Time { return f.now },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 100; i++ {
		if conn, err := net.Dial("unix", f.server.Socket); err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.client = Client{Socket: f.server.Socket}
	return f
}

func me() uint32 { return uint32(os.Getuid()) }

func (f *fixture) do(t *testing.T, request Request) Response {
	t.Helper()
	response, err := f.client.Do(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (f *fixture) entries(t *testing.T) []Entry {
	t.Helper()
	file, err := os.Open(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out []Entry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		out = append(out, entry)
	}
	return out
}

func TestAnUnlistedCallerIsDeniedAndAudited(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always an operator")
	}
	f := start(t, Access{APIVersion: APIVersion})
	response := f.do(t, Request{Operation: OpStatus})
	if response.OK || !strings.Contains(response.Error, "may not") {
		t.Fatalf("response = %#v", response)
	}
	entries := f.entries(t)
	if len(entries) != 1 || entries[0].Error != "denied" || entries[0].Peer.UID != me() || entries[0].Peer.PID == 0 {
		t.Fatalf("audit = %#v", entries)
	}
}

func TestAnObserverReadsButCannotChange(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always an operator")
	}
	f := start(t, Access{APIVersion: APIVersion, Observers: []uint32{me()}})
	status := f.do(t, Request{Operation: OpStatus})
	if !status.OK || strings.Contains(string(status.Result), "s3cr3t") || !strings.Contains(string(status.Result), "[redacted]") {
		t.Fatalf("status = %#v", status)
	}
	prepare := f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeRotate, Users: []string{"alice"}}})
	if prepare.OK {
		t.Fatal("an observer prepared a change")
	}
}

func TestAPreparedTicketCommitsOnceAndOnlyBeforeItExpires(t *testing.T) {
	f := start(t, Access{APIVersion: APIVersion, Operators: []uint32{me()}})
	prepare := f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeSettings, Ports: map[string]uint16{"awg-in": 10870}}})
	if !prepare.OK || strings.Contains(prepare.Output, "s3cr3t") {
		t.Fatalf("prepare = %#v", prepare)
	}
	var ticket Ticket
	if err := json.Unmarshal(prepare.Result, &ticket); err != nil || ticket.ID == "" {
		t.Fatalf("ticket = %s, %v", prepare.Result, err)
	}
	commit := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID})
	if !commit.OK || f.backend.commits != 1 {
		t.Fatalf("commit = %#v", commit)
	}
	if again := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID}); again.OK || f.backend.commits != 1 {
		t.Fatal("a ticket committed twice")
	}

	prepare = f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeRollback}})
	if err := json.Unmarshal(prepare.Result, &ticket); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(11 * time.Minute)
	if expired := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID}); expired.OK {
		t.Fatal("an expired ticket committed")
	}

	entries := f.entries(t)
	var committed *Entry
	for i := range entries {
		if entries[i].Operation == OpCommit && entries[i].OK {
			committed = &entries[i]
		}
	}
	if committed == nil || committed.Transaction != "tx-3" || committed.Change != "settings: ports awg-in=10870" {
		t.Fatalf("audit = %#v", entries)
	}
}

func TestAFailedCommitIsReportedAndCannotBeRetried(t *testing.T) {
	f := start(t, Access{APIVersion: APIVersion, Operators: []uint32{me()}})
	f.backend.commitErr = errors.New("health wait failed near s3cr3t-value-123")
	prepare := f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeImage, Image: "repo/core:next"}})
	var ticket Ticket
	_ = json.Unmarshal(prepare.Result, &ticket)
	commit := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID})
	if commit.OK || strings.Contains(commit.Error, "s3cr3t") {
		t.Fatalf("commit = %#v", commit)
	}
	if retry := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID}); retry.OK || f.backend.commits != 1 {
		t.Fatal("a failed ticket was retried")
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	f := start(t, Access{APIVersion: APIVersion, Operators: []uint32{me()}})
	for _, body := range []string{
		`{"apiVersion":"` + APIVersion + `","operation":"status","command":"rm -rf /"}`,
		`{"apiVersion":"other","operation":"status"}`,
		`{"apiVersion":"` + APIVersion + `","operation":"exec"}`,
	} {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", f.server.Socket)
		}}
		resp, err := (&http.Client{Transport: transport}).Post("http://control/v1", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, resp.StatusCode)
		}
	}
	for _, change := range []Change{
		{Kind: ChangeSettings},
		{Kind: ChangeSettings, Ports: map[string]uint16{"awg-in": 1}, Image: "x"},
		{Kind: ChangeSettings, Enable: []string{"awg-in"}, Disable: []string{"awg-in"}},
		{Kind: ChangeImage},
		{Kind: ChangeRotate},
		{Kind: "shell"},
	} {
		copied := change
		if response := f.do(t, Request{Operation: OpPrepare, Change: &copied}); response.OK {
			t.Errorf("change %#v was accepted", change)
		}
	}
}

func TestAccessFileMustBeRootOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	if err := os.WriteFile(path, []byte(`{"apiVersion":"`+APIVersion+`","observers":[],"operators":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAccess(path)
	if os.Getuid() != 0 && err == nil {
		t.Fatal("a file owned by an unprivileged user was trusted")
	}
}

func TestTheManagedAllowListAddsServiceAccountsWithoutOverridingTheOperator(t *testing.T) {
	operator := Access{APIVersion: APIVersion, Operators: []uint32{1000}, SocketGroup: 7}
	merged := MergeAccess(operator, &Access{Operators: []uint32{993, 1000}, Observers: []uint32{5}, SocketGroup: 984})
	if len(merged.Operators) != 2 || merged.SocketGroup != 7 || len(merged.Observers) != 1 {
		t.Fatalf("merged = %#v", merged)
	}
	if got := MergeAccess(Access{}, &Access{SocketGroup: 984}).SocketGroup; got != 984 {
		t.Fatalf("an unset operator socket group did not take bootstrap's: %d", got)
	}
}
