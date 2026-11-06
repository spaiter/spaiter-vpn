package apply

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRuntimeSyncWaitsForACoreThatIsStillStarting is the acceptance finding:
// a supported migration that also changed the image recreated the core and
// asked its management API to apply before it was listening, which failed
// the apply and its rollback alike.
func TestRuntimeSyncWaitsForACoreThatIsStillStarting(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	h := newHarness(t)
	h.options.ApplyRuntime = nil
	if err := os.MkdirAll(filepath.Dir(h.layout.ConfigPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":%q,"secret":"s3cret"}}}`, addr)
	if err := os.WriteFile(h.layout.ConfigPath(), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	applied := make(chan struct{}, 1)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/manage/apply" && r.Header.Get("Authorization") == "Bearer s3cret" {
				applied <- struct{}{}
			}
			w.Write([]byte(`{}`))
		}))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.options.applyRuntime(ctx); err != nil {
		t.Fatalf("the sync did not wait for the core: %v", err)
	}
	select {
	case <-applied:
	default:
		t.Fatal("the management API never received the apply")
	}
}
