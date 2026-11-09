package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatedBackend is a fakeBackend whose self-test blocks until released and whose
// Prepare can fail, to hold the daemon in the states a real apply creates.
type gatedBackend struct {
	fakeBackend
	started    chan struct{}
	release    chan struct{}
	prepareErr error
}

func (g *gatedBackend) SelfTest(ctx context.Context, out io.Writer) error {
	close(g.started)
	<-g.release
	return nil
}

func (g *gatedBackend) Prepare(ctx context.Context, change Change, out io.Writer) (Prepared, error) {
	if g.prepareErr != nil {
		return Prepared{}, g.prepareErr
	}
	return g.fakeBackend.Prepare(ctx, change, out)
}

// startWith is start() for a caller-supplied backend.
func startWith(t *testing.T, access Access, backend Backend) *fixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fixture{audit: filepath.Join(dir, "audit.log"), now: time.Unix(1000, 0)}
	f.server = &Server{
		Socket: filepath.Join(dir, "c.sock"), Access: access, Backend: backend,
		Audit: &Audit{Path: f.audit}, Now: func() time.Time { return f.now },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 200; i++ {
		if conn, err := net.Dial("unix", f.server.Socket); err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.client = Client{Socket: f.server.Socket}
	return f
}

func operatorAccess() Access {
	return Access{APIVersion: APIVersion, Operators: []uint32{me()}}
}

func (f *fixture) ticketCount() int {
	f.server.mu.Lock()
	defer f.server.mu.Unlock()
	return len(f.server.tickets)
}

func TestOnlyOneMutatingOperationRunsAtATime(t *testing.T) {
	g := &gatedBackend{started: make(chan struct{}), release: make(chan struct{})}
	f := startWith(t, operatorAccess(), g)

	first := make(chan Response, 1)
	go func() {
		r, _ := f.client.Do(context.Background(), Request{Operation: OpSelfTest})
		first <- r
	}()
	select {
	case <-g.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the self-test never started")
	}

	// A second self-test, and a commit, are told "busy" rather than queued.
	if r := f.do(t, Request{Operation: OpSelfTest}); r.OK || !strings.Contains(r.Error, "in progress") {
		t.Fatalf("second self-test = %#v", r)
	}
	prepared := f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeRollback}})
	var ticket Ticket
	if err := json.Unmarshal(prepared.Result, &ticket); err != nil || ticket.ID == "" {
		t.Fatalf("prepare while busy: %#v %v (planning does not mutate and must still work)", prepared, err)
	}
	if r := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID}); r.OK || !strings.Contains(r.Error, "in progress") {
		t.Fatalf("commit during a self-test = %#v", r)
	}
	if g.commits != 0 {
		t.Fatalf("a commit ran beside a self-test: %d", g.commits)
	}

	close(g.release)
	select {
	case r := <-first:
		if !r.OK {
			t.Fatalf("the first self-test = %#v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first self-test never finished")
	}
	// The lock is free again; and the ticket that bounced off "busy" was spent
	// before it ran, so it needs a fresh review.
	if r := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID}); r.OK {
		t.Fatal("a ticket that met a busy daemon was still usable")
	}
}

func TestPrepareNeedsAValidChangeAndFailureLeavesNoTicket(t *testing.T) {
	g := &gatedBackend{}
	f := startWith(t, operatorAccess(), g)

	for name, request := range map[string]Request{
		"no change":         {Operation: OpPrepare},
		"settings but none": {Operation: OpPrepare, Change: &Change{Kind: ChangeSettings}},
		"unknown kind":      {Operation: OpPrepare, Change: &Change{Kind: "reformat"}},
	} {
		if r := f.do(t, request); r.OK || r.Error == "" {
			t.Errorf("%s was accepted: %#v", name, r)
		}
	}
	g.prepareErr = errors.New("port 10870 is taken")
	if r := f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeSettings, Ports: map[string]uint16{"awg-in": 10870}}}); r.OK || !strings.Contains(r.Error, "port 10870") {
		t.Fatalf("a planner refusal must reach the caller: %#v", r)
	}
	if n := f.ticketCount(); n != 0 {
		t.Fatalf("%d tickets exist after only refused prepares", n)
	}
	for _, e := range f.entries(t) {
		if e.OK {
			t.Errorf("a refused request was audited as ok: %+v", e)
		}
	}
}

func TestATicketIsUsableOnlyByTheCallerWhoPreparedIt(t *testing.T) {
	f := startWith(t, operatorAccess(), &fakeBackend{})
	backend := f.server.Backend.(*fakeBackend)

	foreign := &pending{
		change:  Change{Kind: ChangeRollback},
		owner:   me() + 1,
		expires: f.now.Add(time.Hour),
		prepared: Prepared{Commit: func(context.Context, io.Writer) (any, string, error) {
			backend.commits++
			return nil, "tx", nil
		}},
	}
	f.server.mu.Lock()
	f.server.tickets["foreign"] = foreign
	f.server.mu.Unlock()

	for _, op := range []Operation{OpCommit, OpCancel} {
		if r := f.do(t, Request{Operation: op, Ticket: "foreign"}); r.OK || !strings.Contains(r.Error, "belongs to another caller") {
			t.Fatalf("%s of someone else's ticket = %#v", op, r)
		}
	}
	if backend.commits != 0 {
		t.Fatal("a ticket was committed by a caller who did not prepare it")
	}
	// A refused attempt must not burn the owner's consent.
	if f.ticketCount() != 1 {
		t.Fatal("the foreign ticket was consumed by a caller who does not own it")
	}
	if r := f.do(t, Request{Operation: OpCommit, Ticket: "does-not-exist"}); r.OK {
		t.Fatal("an unknown ticket committed")
	}
}

func TestCancelSpendsTheTicketWithoutRunningIt(t *testing.T) {
	f := startWith(t, operatorAccess(), &fakeBackend{})
	backend := f.server.Backend.(*fakeBackend)
	prepared := f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeImage, Image: "repo/core:next"}})
	var ticket Ticket
	if err := json.Unmarshal(prepared.Result, &ticket); err != nil {
		t.Fatal(err)
	}
	if r := f.do(t, Request{Operation: OpCancel, Ticket: ticket.ID}); !r.OK {
		t.Fatalf("cancel = %#v", r)
	}
	if backend.commits != 0 || f.ticketCount() != 0 {
		t.Fatalf("commits=%d tickets=%d after a cancel", backend.commits, f.ticketCount())
	}
	if r := f.do(t, Request{Operation: OpCommit, Ticket: ticket.ID}); r.OK {
		t.Fatal("a cancelled ticket committed")
	}
	var cancelled *Entry
	entries := f.entries(t)
	for i := range entries {
		if entries[i].Operation == OpCancel {
			cancelled = &entries[i]
		}
	}
	if cancelled == nil || !cancelled.OK || cancelled.Change != "image: image repo/core:next" || cancelled.Ticket != ticket.ID {
		t.Fatalf("cancel audit = %+v", cancelled)
	}
}

func TestExpiredTicketsAreSweptWhenAnotherIsPrepared(t *testing.T) {
	f := startWith(t, operatorAccess(), &fakeBackend{})
	for i := 0; i < 3; i++ {
		f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeRollback}})
	}
	if f.ticketCount() != 3 {
		t.Fatalf("tickets = %d, want 3", f.ticketCount())
	}
	f.now = f.now.Add(11 * time.Minute)
	f.do(t, Request{Operation: OpPrepare, Change: &Change{Kind: ChangeRollback}})
	if n := f.ticketCount(); n != 1 {
		t.Fatalf("tickets = %d after the TTL passed, want only the new one: forgotten tickets must not pile up", n)
	}
}

func TestReadOperationsReturnRedactedResults(t *testing.T) {
	if me() == 0 {
		t.Skip("root is always an operator, so there is no observer to be refused")
	}
	f := startWith(t, Access{APIVersion: APIVersion, Observers: []uint32{me()}}, &fakeBackend{})
	status := f.do(t, Request{Operation: OpStatus})
	if !status.OK || strings.Contains(string(status.Result), "s3cr3t") || !strings.Contains(string(status.Result), "[redacted]") {
		t.Fatalf("status = %#v", status)
	}
	gens := f.do(t, Request{Operation: OpGenerations})
	if !gens.OK || strings.ReplaceAll(string(gens.Result), " ", "") != "[1,2]" {
		t.Fatalf("generations = %#v", gens)
	}
	// Preflight reveals planning detail: an observer may not run it.
	if r := f.do(t, Request{Operation: OpPreflight}); r.OK {
		t.Fatalf("an observer ran a preflight: %#v", r)
	}
}

func TestPreflightStreamsItsOutputToAnOperator(t *testing.T) {
	f := startWith(t, operatorAccess(), &fakeBackend{})
	r := f.do(t, Request{Operation: OpPreflight})
	if !r.OK || !strings.Contains(r.Output, "preflight ok") {
		t.Fatalf("preflight = %#v", r)
	}
}

func TestTicketIDsAreLongRandomAndUnique(t *testing.T) {
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id, err := newTicketID()
		if err != nil {
			t.Fatal(err)
		}
		if !hex32.MatchString(id) {
			t.Fatalf("ticket id %q is not 128 bits of hex", id)
		}
		if seen[id] {
			t.Fatalf("ticket id %q repeated", id)
		}
		seen[id] = true
	}
}

func TestChangeValidateRejectsWhatDoesNotBelongToItsKind(t *testing.T) {
	ports := map[string]uint16{"awg-in": 10870}
	for _, tc := range []struct {
		name    string
		change  Change
		wantErr string // empty: valid
	}{
		{"ports", Change{Kind: ChangeSettings, Ports: ports}, ""},
		{"mtu only", Change{Kind: ChangeSettings, MTU: map[string]uint32{"awg-in": 1280}}, ""},
		{"enable and disable different protocols", Change{Kind: ChangeSettings, Enable: []string{"a"}, Disable: []string{"b"}}, ""},
		{"image", Change{Kind: ChangeImage, Image: "repo/core:next"}, ""},
		{"rotate", Change{Kind: ChangeRotate, Users: []string{"alice"}}, ""},
		{"rollback latest", Change{Kind: ChangeRollback}, ""},
		{"rollback to a generation", Change{Kind: ChangeRollback, Generation: 4}, ""},

		{"empty settings", Change{Kind: ChangeSettings}, "names no port"},
		{"settings with an image", Change{Kind: ChangeSettings, Ports: ports, Image: "x"}, "fields of another kind"},
		{"settings with users", Change{Kind: ChangeSettings, Ports: ports, Users: []string{"u"}}, "fields of another kind"},
		{"settings with a generation", Change{Kind: ChangeSettings, Ports: ports, Generation: 2}, "fields of another kind"},
		{"zero port", Change{Kind: ChangeSettings, Ports: map[string]uint16{"awg-in": 0}}, "is zero"},
		{"enabled and disabled", Change{Kind: ChangeSettings, Enable: []string{"a"}, Disable: []string{"a"}}, "both enabled and disabled"},
		{"named twice", Change{Kind: ChangeSettings, Enable: []string{"a", "a"}}, "named twice"},
		{"image without a reference", Change{Kind: ChangeImage}, "exactly one image"},
		{"image with ports", Change{Kind: ChangeImage, Image: "x", Ports: ports}, "exactly one image"},
		{"rotate nobody", Change{Kind: ChangeRotate}, "names its users"},
		{"rotate with an image", Change{Kind: ChangeRotate, Users: []string{"u"}, Image: "x"}, "names its users"},
		{"rollback with an image", Change{Kind: ChangeRollback, Image: "x"}, "at most a generation"},
		{"rollback with users", Change{Kind: ChangeRollback, Users: []string{"u"}}, "at most a generation"},
		{"unknown kind", Change{Kind: "wipe"}, "unknown change kind"},
		{"no kind", Change{}, "unknown change kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.change.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestChangeSummaryIsTypedSortedAndCarriesNoFreeText(t *testing.T) {
	for _, tc := range []struct {
		change Change
		want   string
	}{
		{Change{Kind: ChangeSettings, Ports: map[string]uint16{"b-in": 2, "a-in": 1}}, "settings: ports a-in=1,b-in=2"},
		{Change{Kind: ChangeSettings, MTU: map[string]uint32{"awg-in": 1280}}, "settings: mtu awg-in=1280"},
		{Change{Kind: ChangeSettings, Ports: map[string]uint16{"a": 1}, MTU: map[string]uint32{"a": 1400}, Enable: []string{"x", "y"}, Disable: []string{"z"}},
			"settings: ports a=1; mtu a=1400; enable x,y; disable z"},
		{Change{Kind: ChangeImage, Image: "repo/core:next"}, "image: image repo/core:next"},
		{Change{Kind: ChangeRotate, Users: []string{"alice", "bob"}}, "rotate: users alice,bob"},
		{Change{Kind: ChangeRollback}, "rollback: generation 0"},
		{Change{Kind: ChangeRollback, Generation: 7}, "rollback: generation 7"},
		{Change{Kind: "unknown"}, "unknown: "},
	} {
		if got := tc.change.Summary(); got != tc.want {
			t.Errorf("Summary() = %q, want %q", got, tc.want)
		}
	}
}

func TestParseAccessIsStrict(t *testing.T) {
	good := `{"apiVersion":"` + APIVersion + `","observers":[1001],"operators":[1000],"socketGroup":7}`
	a, err := parseAccess("control.json", []byte(good))
	if err != nil || len(a.Observers) != 1 || a.Operators[0] != 1000 || a.SocketGroup != 7 {
		t.Fatalf("good document: %+v, %v", a, err)
	}
	for name, doc := range map[string]string{
		"unknown field (a typo must not drop a uid)": `{"apiVersion":"` + APIVersion + `","operatros":[1000]}`,
		"foreign apiVersion":                         `{"apiVersion":"control/v99","operators":[1000]}`,
		"missing apiVersion":                         `{"operators":[1000]}`,
		"not json":                                   `operators: [1000]`,
		"wrong type":                                 `{"apiVersion":"` + APIVersion + `","operators":"1000"}`,
		"empty":                                      ``,
	} {
		if _, err := parseAccess("control.json", []byte(doc)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestLoadAccessRefusesWhatItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadAccess(filepath.Join(dir, "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if _, err := LoadAccess(dir); err == nil || !strings.Contains(err.Error(), "regular file owned by root") {
		t.Errorf("a directory: %v", err)
	}
	target := filepath.Join(dir, "real.json")
	os.WriteFile(target, []byte(`{"apiVersion":"`+APIVersion+`"}`), 0o600)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccess(link); err == nil || !strings.Contains(err.Error(), "regular file owned by root") {
		t.Errorf("a symlink must not be followed to a file somebody else may swap: %v", err)
	}
	if os.Getuid() != 0 {
		os.Chmod(target, 0o600)
		if _, err := LoadAccess(target); err == nil {
			t.Error("a file owned by this unprivileged user was trusted")
		}
	}
}

// shortDir avoids t.TempDir(), whose path embeds the test name and can pass the
// 108-byte limit of a unix socket address.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestListenCreatesAPrivateSocketAndReplacesAStaleOne(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "run", "nested", "c.sock")
	s := &Server{Socket: sock}

	l, err := s.listen()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(sock)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no socket at %s: %v", sock, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want 0600: with no socket group only the owner may connect", info.Mode().Perm())
	}
	// Leave the file behind, as a crashed daemon would.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("the stale socket was not left for the test: %v", err)
	}
	l2, err := s.listen()
	if err != nil {
		t.Fatalf("a stale socket blocked the restart: %v", err)
	}
	l2.Close()
}

func TestListenLeavesAFileThatIsNotASocketAlone(t *testing.T) {
	path := filepath.Join(shortDir(t), "c.sock")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (&Server{Socket: path}).listen()
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("err = %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "precious" {
		t.Fatalf("the file was destroyed: %q", data)
	}
}

func TestListenWithAGroupItCannotGrantFailsAndLeavesNoSocket(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chown to any group")
	}
	sock := filepath.Join(shortDir(t), "c.sock")
	_, err := (&Server{Socket: sock, Access: Access{SocketGroup: 4242}}).listen()
	if err == nil {
		t.Fatal("an unprivileged chown to root succeeded?")
	}
	if _, statErr := os.Lstat(sock); statErr == nil {
		t.Fatal("a half-configured socket was left listening")
	}
}

func TestPeerOfReportsTheKernelsViewOfTheCaller(t *testing.T) {
	sock := filepath.Join(shortDir(t), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	peer, err := peerOf(server)
	if err != nil {
		t.Fatal(err)
	}
	if peer.UID != uint32(os.Getuid()) || peer.GID != uint32(os.Getgid()) || peer.PID != int32(os.Getpid()) {
		t.Fatalf("peer = %+v, want uid=%d gid=%d pid=%d", peer, os.Getuid(), os.Getgid(), os.Getpid())
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := peerOf(a); err == nil {
		t.Fatal("a non-unix connection produced credentials")
	}
}

func TestAuditRecordsAppendOnlyPrivateAndNeverFailTheRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "control.log")
	fixed := time.Date(2026, 11, 7, 12, 0, 0, 0, time.FixedZone("x", 3600))
	a := &Audit{Path: path, Now: func() time.Time { return fixed }}

	a.Record(Entry{Operation: OpStatus, Peer: Peer{UID: 5}})
	a.Record(Entry{Operation: OpCommit, Error: "denied"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want one per record: %q", len(lines), data)
	}
	var first, second Entry
	if json.Unmarshal([]byte(lines[0]), &first) != nil || json.Unmarshal([]byte(lines[1]), &second) != nil {
		t.Fatalf("not JSON lines: %q", data)
	}
	if !first.OK || second.OK || second.Error != "denied" {
		t.Errorf("ok must follow the absence of an error: %+v / %+v", first, second)
	}
	if !first.Time.Equal(fixed) || first.Time.Location() != time.UTC {
		t.Errorf("time = %v (%v), want %v in UTC", first.Time, first.Time.Location(), fixed)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("log mode = %v: it names who changed what", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Errorf("log directory mode = %v", info.Mode().Perm())
	}

	var nilAudit *Audit
	nilAudit.Record(Entry{}) // a daemon without an audit log must not crash

	var failures []error
	blocked := &Audit{Path: filepath.Join(path, "under-a-file", "x.log"), Failed: func(err error) { failures = append(failures, err) }}
	blocked.Record(Entry{Operation: OpStatus})
	if len(failures) != 1 {
		t.Fatalf("a write failure was not reported: %v", failures)
	}
	(&Audit{Path: filepath.Join(path, "x", "y")}).Record(Entry{}) // no Failed handler: still no panic
}

func TestConcurrentAuditRecordsStayWholeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	a := &Audit{Path: path}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a.Record(Entry{Operation: OpStatus, Change: fmt.Sprintf("n=%d", i)})
		}(i)
	}
	wg.Wait()
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 40 {
		t.Fatalf("%d lines for 40 records", len(lines))
	}
	for _, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("interleaved write: %q", line)
		}
	}
}
