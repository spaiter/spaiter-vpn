package cli

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// servePprof exposes the runtime profiles of this process over HTTP on addr
// and keeps serving until ctx is done. An empty addr disables it.
//
// The handlers are registered on a private mux rather than through the
// net/http/pprof side effect on http.DefaultServeMux, so that nothing else
// in the binary can be reached through this listener by accident. The
// address is meant to be a loopback one: the profiles name goroutines,
// files and users' peer names, and the bot already has a public port.
//
// Everything net/http/pprof knows is served, including the goroutineleak
// profile Go 1.27 made generally available: pprof.Index looks the profile
// name up at request time, so new profile kinds appear here without a code
// change.
func servePprof(ctx context.Context, addr string, log *slog.Logger) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("pprof server stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("pprof listening", "addr", ln.Addr().String())
	return nil
}
