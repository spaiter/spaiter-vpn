package servicetest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// Handler serves the fake core over the same HTTP API the fork exposes, so
// code that builds its own manage.Client (the bot command) can be pointed at
// it. Requests without the right bearer secret are refused, as the core does.
func (f *API) Handler(secret string) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		switch {
		case errors.Is(err, manage.ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, manage.ErrBadRequest):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(v)
		}
	}
	body := func(r *http.Request) json.RawMessage {
		data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		return data
	}

	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, map[string]string{"version": "fake"}, nil)
	})
	mux.HandleFunc("GET /manage/inbounds", func(w http.ResponseWriter, r *http.Request) {
		list, err := f.Inbounds(r.Context())
		reply(w, list, err)
	})
	mux.HandleFunc("GET /manage/inbounds/{tag}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := f.Inbound(r.Context(), r.PathValue("tag"))
		reply(w, raw, err)
	})
	mux.HandleFunc("GET /manage/inbounds/{tag}/users", func(w http.ResponseWriter, r *http.Request) {
		users, err := f.Users(r.Context(), r.PathValue("tag"))
		if users == nil {
			users = []json.RawMessage{}
		}
		reply(w, users, err)
	})
	mux.HandleFunc("POST /manage/inbounds/{tag}/users", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"message": "ok"}, f.AddUser(r.Context(), r.PathValue("tag"), body(r)))
	})
	mux.HandleFunc("DELETE /manage/inbounds/{tag}/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"message": "ok"}, f.DeleteUser(r.Context(), r.PathValue("tag"), r.PathValue("name")))
	})
	mux.HandleFunc("GET /manage/endpoints", func(w http.ResponseWriter, r *http.Request) {
		list, err := f.Endpoints(r.Context())
		reply(w, list, err)
	})
	mux.HandleFunc("GET /manage/endpoints/{tag}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := f.Endpoint(r.Context(), r.PathValue("tag"))
		reply(w, raw, err)
	})
	mux.HandleFunc("PUT /manage/endpoints/{tag}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"message": "ok"}, f.PutEndpoint(r.Context(), r.PathValue("tag"), body(r)))
	})
	mux.HandleFunc("POST /manage/apply", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.applies++
		f.mu.Unlock()
		reply(w, manage.ApplyResult{Message: "ok"}, nil)
	})
	mux.HandleFunc("GET /stats/users", func(w http.ResponseWriter, r *http.Request) {
		rows, err := f.UserStats(r.Context())
		if rows == nil {
			rows = []manage.UserStat{}
		}
		reply(w, rows, err)
	})
	mux.HandleFunc("DELETE /stats/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"message": "ok"}, f.ResetUserStats(r.Context(), r.PathValue("name")))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// HTTPApplies is how many times the core was asked to apply over HTTP.
func (f *API) HTTPApplies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies
}

// Serve starts the fake core on a loopback port and returns the controller
// address and the secret a client needs, with a core config file naming them
// the way the real one does.
func (f *Fixture) Serve(t *testing.T, dir string) (controller, secret, corePath string) {
	t.Helper()
	secret = "fixture-secret"
	srv := httptest.NewServer(f.API.Handler(secret))
	t.Cleanup(srv.Close)
	controller = strings.TrimPrefix(srv.URL, "http://")
	corePath = dir + "/core.json"
	doc := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":%q,"secret":%q}}}`, controller, secret)
	if err := writeFile(corePath, doc); err != nil {
		t.Fatalf("write core config: %v", err)
	}
	return controller, secret, corePath
}
