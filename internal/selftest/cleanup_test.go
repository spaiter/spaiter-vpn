package selftest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/manage"
)

func TestCleanupVerifiesAPIAndPersistedState(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		calls      int
	}{
		{"success", "", 2}, {"delete-fails", "delete endpoint", 1},
		{"apply-fails", "apply the removal", 2}, {"not-removed", "did not report", 2},
		{"stale-config", "still mentions", 2}, {"missing-config", "read", 2},
		{"port-still-bound", "still bound", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			config := "{}"
			if tc.name == "stale-config" {
				config = `{"tag":"bt-selftest-in"}`
			}
			if tc.name != "missing-config" {
				if err := os.WriteFile(path, []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Port zero cannot occur in /proc: the kernel assigns a real ephemeral
			// port when asked to bind zero. The occupied case owns a real UDP socket.
			opts := DefaultOptions()
			opts.Port = 0
			if tc.name == "port-still-bound" {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				opts.Port = uint16(conn.LocalAddr().(*net.UDPAddr).Port)
			}
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				if r.Header.Get("Authorization") != "Bearer test-only" {
					http.Error(w, "bad auth", 401)
					return
				}
				switch r.Method + " " + r.URL.Path {
				case "DELETE /manage/endpoints/bt-selftest-in":
					if tc.name == "delete-fails" {
						http.Error(w, "delete refused", 500)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				case "POST /manage/apply":
					if tc.name == "apply-fails" {
						http.Error(w, "apply refused", 500)
						return
					}
					if tc.name == "not-removed" {
						fmt.Fprint(w, `{"endpoints":{}}`)
						return
					}
					fmt.Fprint(w, `{"endpoints":{"removed":["bt-selftest-in"]}}`)
				default:
					http.Error(w, "unexpected request", 400)
				}
			}))
			defer server.Close()
			client, err := manage.New(server.URL, "test-only")
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = cleanup(context.Background(), &out, client, opts, &LiveConfig{Path: path})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			server.Close()
			want := []string{"DELETE /manage/endpoints/bt-selftest-in", "POST /manage/apply"}[:tc.calls]
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("requests = %v, want %v", calls, want)
			}
			if tc.want != "" && strings.Contains(out.String(), "production endpoints verified") {
				t.Fatalf("false success: %s", out.String())
			}
		})
	}
}

func TestRunCleansEndpointAfterApplyFailureEvenWhenCanceled(t *testing.T) {
	for _, cancelRun := range []bool{false, true} {
		t.Run(fmt.Sprint("cancel=", cancelRun), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []string
			applies := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				switch r.Method + " " + r.URL.Path {
				case "POST /manage/endpoints":
					w.WriteHeader(http.StatusCreated)
				case "POST /manage/apply":
					applies++
					if applies == 1 {
						if cancelRun {
							cancel()
						}
						http.Error(w, "apply failed", 500)
						return
					}
					fmt.Fprint(w, `{"endpoints":{"removed":["bt-selftest-in"]}}`)
				case "DELETE /manage/endpoints/bt-selftest-in":
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected request", 400)
				}
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"endpoints":[]}`), 0600); err != nil {
				t.Fatal(err)
			}
			opts := DefaultOptions()
			opts.ConfigPath = path
			opts.LogPath = filepath.Join(t.TempDir(), "unused.log")
			opts.Controller = server.URL
			opts.Secret = "test-only"
			opts.Port = 0
			// The failure precedes tunnel creation, so this exercises the real Run
			// lifecycle without root, interfaces, Docker or a running VPN instance.
			_, err := Run(ctx, io.Discard, opts)
			if err == nil || !strings.Contains(err.Error(), "apply test endpoint") {
				t.Fatalf("error = %v", err)
			}
			server.Close()
			want := []string{"POST /manage/endpoints", "POST /manage/apply", "DELETE /manage/endpoints/bt-selftest-in", "POST /manage/apply"}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("cleanup sequence = %v", calls)
			}
		})
	}
}
