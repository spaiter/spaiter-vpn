package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Prepared is a planned change waiting for consent.
type Prepared struct {
	// Plan is shown to the caller; it must not contain secrets.
	Plan any
	// Commit applies exactly what Plan describes, or refuses.
	Commit func(ctx context.Context, out io.Writer) (result any, transaction string, err error)
}

// Backend performs the operations. The CLI implements it over the same
// planner and engine `bootstrap` uses; this package only decides who may ask.
type Backend interface {
	Status(ctx context.Context) (any, error)
	Generations(ctx context.Context) (any, error)
	Preflight(ctx context.Context, out io.Writer) (any, error)
	Prepare(ctx context.Context, change Change, out io.Writer) (Prepared, error)
	SelfTest(ctx context.Context, out io.Writer) error
	// Redact scrubs deployment secrets from text bound for a caller or the log.
	Redact(text string) string
}

// Access maps kernel-verified uids to roles. Root is always an operator.
type Access struct {
	APIVersion string   `json:"apiVersion"`
	Observers  []uint32 `json:"observers"`
	Operators  []uint32 `json:"operators"`
	// SocketGroup owns the socket, mode 0660, as a second fence in front of
	// the uid check. Zero leaves it root-only.
	SocketGroup uint32 `json:"socketGroup"`
}

func (a Access) role(uid uint32) (Role, bool) {
	if uid == 0 {
		return RoleOperator, true
	}
	for _, id := range a.Operators {
		if id == uid {
			return RoleOperator, true
		}
	}
	for _, id := range a.Observers {
		if id == uid {
			return RoleObserver, true
		}
	}
	return "", false
}

func allows(have, need Role) bool {
	return have == RoleOperator || have == need
}

// LoadAccess reads the access file. It must be root-owned and writable by
// root only: whoever can edit it can grant themselves the operator role.
func LoadAccess(path string) (Access, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Access{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return Access{}, fmt.Errorf("%s must be a regular file owned by root and writable only by root", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Access{}, err
	}
	var access Access
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&access); err != nil {
		return Access{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if access.APIVersion != APIVersion {
		return Access{}, fmt.Errorf("%s has apiVersion %q, want %q", path, access.APIVersion, APIVersion)
	}
	return access, nil
}

// MergeAccess unions an operator's allow-list with the one bootstrap manages
// for its own service accounts (the bot, the web UI). Each file keeps one
// owner: the operator's edits are never rewritten, and bootstrap can add or
// drop a service without touching them. The operator's socket group wins
// when set.
func MergeAccess(operator Access, managed *Access) Access {
	if managed == nil {
		return operator
	}
	out := operator
	out.Observers = unionUIDs(operator.Observers, managed.Observers)
	out.Operators = unionUIDs(operator.Operators, managed.Operators)
	if out.SocketGroup == 0 {
		out.SocketGroup = managed.SocketGroup
	}
	return out
}

func unionUIDs(a, b []uint32) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, list := range [][]uint32{a, b} {
		for _, uid := range list {
			if !seen[uid] {
				seen[uid] = true
				out = append(out, uid)
			}
		}
	}
	return out
}

// Server serves one socket.
type Server struct {
	Socket  string
	Access  Access
	Backend Backend
	Audit   *Audit
	// TicketTTL bounds how long consent stays valid. The engine recomputes
	// the plan on commit anyway; the TTL keeps a forgotten ticket from being
	// committed days later against a host nobody reviewed.
	TicketTTL time.Duration
	Now       func() time.Time

	mu      sync.Mutex
	tickets map[string]*pending
	// mutating serialises commits and self-tests. The engine's own lock
	// would too, but a second caller should be told "busy", not block.
	mutating sync.Mutex
}

type pending struct {
	change   Change
	prepared Prepared
	owner    uint32
	expires  time.Time
}

type peerKey struct{}

// Serve listens until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	if s.TicketTTL == 0 {
		s.TicketTTL = 10 * time.Minute
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	s.tickets = map[string]*pending{}
	listener, err := s.listen()
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			peer, err := peerOf(conn)
			if err != nil {
				return ctx
			}
			return context.WithValue(ctx, peerKey{}, peer)
		},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) listen() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0o755); err != nil {
		return nil, err
	}
	// A stale socket from a previous run is removed; anything else at that
	// path is not ours and is left alone.
	if info, err := os.Lstat(s.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", s.Socket)
		}
		if err := os.Remove(s.Socket); err != nil {
			return nil, err
		}
	}
	old := unix.Umask(0o177)
	listener, err := net.Listen("unix", s.Socket)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	if s.Access.SocketGroup != 0 {
		if err := os.Chown(s.Socket, 0, int(s.Access.SocketGroup)); err != nil {
			listener.Close()
			return nil, err
		}
		if err := os.Chmod(s.Socket, 0o660); err != nil {
			listener.Close()
			return nil, err
		}
	}
	return listener, nil
}

func peerOf(conn net.Conn) (Peer, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if credErr != nil {
		return Peer{}, credErr
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	respond := func(status int, response Response) {
		response.APIVersion = APIVersion
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1" {
		respond(http.StatusNotFound, Response{Error: "the only endpoint is POST /v1"})
		return
	}
	peer, ok := r.Context().Value(peerKey{}).(Peer)
	if !ok {
		respond(http.StatusForbidden, Response{Error: "the caller's credentials could not be read"})
		return
	}
	var request Request
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.APIVersion != APIVersion {
		s.Audit.Record(Entry{Peer: peer, Operation: request.Operation, Error: "malformed request"})
		respond(http.StatusBadRequest, Response{Error: fmt.Sprintf("malformed request; want apiVersion %s", APIVersion)})
		return
	}
	need, known := request.Operation.Requires()
	if !known {
		s.Audit.Record(Entry{Peer: peer, Operation: request.Operation, Error: "unknown operation"})
		respond(http.StatusBadRequest, Response{Error: fmt.Sprintf("unknown operation %q", request.Operation)})
		return
	}
	have, granted := s.Access.role(peer.UID)
	if !granted || !allows(have, need) {
		s.Audit.Record(Entry{Peer: peer, Operation: request.Operation, Error: "denied"})
		respond(http.StatusForbidden, Response{Error: fmt.Sprintf("uid %d may not %s", peer.UID, request.Operation)})
		return
	}

	var output bytes.Buffer
	result, entry, err := s.dispatch(r.Context(), peer, request, &output)
	entry.Peer, entry.Operation = peer, request.Operation
	response := Response{OK: err == nil, Output: s.Backend.Redact(output.String())}
	if err != nil {
		entry.Error = s.Backend.Redact(err.Error())
		response.Error = entry.Error
	} else if result != nil {
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			response.OK, response.Error = false, marshalErr.Error()
		} else {
			response.Result = json.RawMessage(s.Backend.Redact(string(encoded)))
		}
	}
	s.Audit.Record(entry)
	status := http.StatusOK
	if err != nil {
		status = http.StatusConflict
	}
	respond(status, response)
}

func (s *Server) dispatch(ctx context.Context, peer Peer, request Request, out io.Writer) (any, Entry, error) {
	var entry Entry
	switch request.Operation {
	case OpStatus:
		result, err := s.Backend.Status(ctx)
		return result, entry, err
	case OpGenerations:
		result, err := s.Backend.Generations(ctx)
		return result, entry, err
	case OpPreflight:
		result, err := s.Backend.Preflight(ctx, out)
		return result, entry, err
	case OpSelfTest:
		if !s.mutating.TryLock() {
			return nil, entry, errBusy
		}
		defer s.mutating.Unlock()
		return nil, entry, s.Backend.SelfTest(context.WithoutCancel(ctx), out)
	case OpPrepare:
		if request.Change == nil {
			return nil, entry, fmt.Errorf("prepare needs a change")
		}
		if err := request.Change.Validate(); err != nil {
			return nil, entry, err
		}
		entry.Change = request.Change.Summary()
		prepared, err := s.Backend.Prepare(ctx, *request.Change, out)
		if err != nil {
			return nil, entry, err
		}
		id, err := newTicketID()
		if err != nil {
			return nil, entry, err
		}
		expires := s.Now().Add(s.TicketTTL)
		s.mu.Lock()
		s.expireLocked()
		s.tickets[id] = &pending{change: *request.Change, prepared: prepared, owner: peer.UID, expires: expires}
		s.mu.Unlock()
		entry.Ticket = id
		return Ticket{ID: id, Change: *request.Change, Plan: prepared.Plan, ExpiresAt: expires}, entry, nil
	case OpCancel, OpCommit:
		entry.Ticket = request.Ticket
		s.mu.Lock()
		s.expireLocked()
		ticket, ok := s.tickets[request.Ticket]
		if ok && ticket.owner == peer.UID {
			// Single use, removed before it runs: a commit that fails
			// halfway must be prepared and reviewed again, not retried.
			delete(s.tickets, request.Ticket)
		}
		s.mu.Unlock()
		if !ok || ticket.owner != peer.UID {
			return nil, entry, fmt.Errorf("no such ticket, it expired, or it belongs to another caller")
		}
		entry.Change = ticket.change.Summary()
		if request.Operation == OpCancel {
			return nil, entry, nil
		}
		if !s.mutating.TryLock() {
			return nil, entry, errBusy
		}
		defer s.mutating.Unlock()
		// Detached from the request: a caller that hangs up mid-apply must not
		// abort it halfway. The engine finishes, or compensates, either way.
		result, transaction, err := ticket.prepared.Commit(context.WithoutCancel(ctx), out)
		entry.Transaction = transaction
		return result, entry, err
	}
	return nil, entry, fmt.Errorf("unhandled operation %q", request.Operation)
}

var errBusy = errors.New("another change is in progress; try again when it finishes")

func (s *Server) expireLocked() {
	now := s.Now()
	for id, ticket := range s.tickets {
		if now.After(ticket.expires) {
			delete(s.tickets, id)
		}
	}
}

func newTicketID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
