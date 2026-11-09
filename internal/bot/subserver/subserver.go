// Package subserver serves the per-user subscription a client polls.
//
// A stable URL per user, which the client refreshes on its own timer, so a
// change the user cannot act on -- a rotated relay pool, a port that moved
// after the line's address changed -- reaches them without anyone re-sending a
// file.
//
// What it serves is a cache built elsewhere. Nothing here provisions anything
// or talks to the core: a poll from a client must not be able to mint
// credentials, and the loop that rebuilds the cache is the only writer.
package subserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Store is the slice of the bot's state this server reads.
type Store interface {
	BundleCache(token string) ([]byte, bool, error)
}

// Server answers subscription polls.
type Server struct {
	store Store
	log   *slog.Logger

	mounts map[string]http.Handler
}

// Mount serves another handler under a path prefix on the same port. The
// Mini App uses it: the port is already reachable from the internet through
// the tunnel, and a second listener would need a second front door.
func (s *Server) Mount(prefix string, h http.Handler) *Server {
	if s.mounts == nil {
		s.mounts = map[string]http.Handler{}
	}
	s.mounts[prefix] = h
	return s
}

// New builds a server over a cache.
func New(store Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: store, log: log}
}

// Handler is the routing, exposed separately so it can be exercised without a
// listener.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/sub/", s.subscription)
	for prefix, h := range s.mounts {
		mux.Handle(prefix, h)
	}
	// Anything else, including "/", answers ok rather than 404: this port sits
	// behind a tunnel and a reverse proxy, both of which probe the root, and a
	// 404 there reads as the service being down.
	mux.HandleFunc("/", s.health)
	return mux
}

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context, listen string) error {
	server := &http.Server{
		Addr:    listen,
		Handler: s.Handler(),
		// A subscription poll is a single small GET. The timeouts are here
		// because this port is reachable from the internet through two
		// different front doors, and a stuck connection should cost nothing.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// stopped releases the watcher when serving ends on its own. Without it
	// the watcher sits on ctx.Done() forever -- which for context.Background()
	// is a nil channel -- and Run never returns the bind error. A port already
	// in use would hang the bot instead of reporting it.
	stopped := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
		case <-stopped:
			return
		}
		// Give a poll in flight a moment to finish rather than cutting it: a
		// truncated subscription is worse than a slightly late shutdown.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
	}()

	s.log.Info("subscription server listening", "listen", listen)
	err := server.ListenAndServe()
	close(stopped)
	<-watcherDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("subserver: %w", err)
	}
	return nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if !allowed(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	if !allowed(w, r) {
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}

	bundle, found, err := s.store.BundleCache(token)
	if err != nil {
		// Deliberately not told apart in the response: a reader cannot be
		// allowed to learn that a token exists but its cache is unreadable.
		s.log.Error("reading a bundle cache failed", "error", err)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// No caching: the point of the URL is that a client polling it sees the
	// current configuration, and an intermediary holding an old copy defeats
	// that silently.
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(bundle); err != nil {
		s.log.Warn("a subscription poll was cut short", "error", err)
	}
}

// allowed restricts the server to reads. Everything here is a GET; answering
// anything else would only invite a mistake.
func allowed(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
}
