package vk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeBrowser is the slice of Chromium's debugger the captcha solver uses: a
// target list over HTTP and a websocket that answers Runtime.evaluate and
// Input.dispatchMouseEvent from a script.
type fakeBrowser struct {
	mu      sync.Mutex
	clicks  int
	evals   []string
	port    int
	onEval  func(expr string) (value any, errMsg string)
	badClik bool
	noTgt   bool
}

func newFakeBrowser(t *testing.T, onEval func(expr string) (any, string)) *fakeBrowser {
	t.Helper()
	b := &fakeBrowser{onEval: onEval}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json" {
			if b.noTgt {
				fmt.Fprint(w, `[{"type":"page","url":"https://example.org/","webSocketDebuggerUrl":"ws://x/y"}]`)
				return
			}
			fmt.Fprintf(w, `[{"type":"page","url":"https://id.vk.com/not_robot_captcha?x=1","webSocketDebuggerUrl":"ws://%s/devtools/page/1"}]`, r.Host)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			_, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			var cmd struct {
				ID     int            `json:"id"`
				Method string         `json:"method"`
				Params map[string]any `json:"params"`
			}
			json.Unmarshal(data, &cmd)
			// An event first: the client must skip frames without its id.
			c.Write(r.Context(), websocket.MessageText, []byte(`{"method":"Page.frameNavigated"}`))
			reply := map[string]any{"id": cmd.ID}
			switch cmd.Method {
			case "Runtime.evaluate":
				expr, _ := cmd.Params["expression"].(string)
				b.mu.Lock()
				b.evals = append(b.evals, expr)
				b.mu.Unlock()
				value, errMsg := b.onEval(expr)
				if errMsg != "" {
					reply["error"] = map[string]any{"message": errMsg}
				} else {
					reply["result"] = map[string]any{"result": map[string]any{"value": value}}
				}
			case "Input.dispatchMouseEvent":
				b.mu.Lock()
				b.clicks++
				bad := b.badClik
				b.mu.Unlock()
				if bad {
					reply["error"] = map[string]any{"message": "no such frame"}
				} else {
					reply["result"] = map[string]any{}
				}
			default:
				reply["result"] = map[string]any{}
			}
			out, _ := json.Marshal(reply)
			c.Write(r.Context(), websocket.MessageText, out)
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	b.port, _ = strconv.Atoi(u.Port())
	return b
}

func solver(t *testing.T, port int) *Relogin {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	r := &Relogin{
		Cfg: ReloginConfig{DebugPort: port, CaptchaWait: 3 * time.Second},
		Log: quietVK(),
	}
	// A clock that only moves when the code sleeps: deadlines expire in
	// simulated time, so the test never really waits.
	r.Now = func() time.Time { return now }
	r.sleep = func(d time.Duration) { now = now.Add(d) }
	return r
}

const checkboxRect = "100,200,40,20"

func evalScript(label string, after func(expr string) (any, string)) func(string) (any, string) {
	return func(expr string) (any, string) {
		switch {
		case strings.Contains(expr, "installed"):
			return "installed", ""
		case strings.Contains(expr, "querySelector('label.vkc__Checkbox"), strings.Contains(expr, "SliderCaptcha"):
			return label, ""
		default:
			return after(expr)
		}
	}
}

func TestCDPSolverClicksTheCheckboxAndSeesTheSuccessToken(t *testing.T) {
	b := newFakeBrowser(t, evalScript(checkboxRect, func(expr string) (any, string) {
		if expr == "window.__wdtt_captcha" {
			return "success", ""
		}
		return nil, ""
	}))
	r := solver(t, b.port)
	if got := r.cdpSolveRobot(context.Background()); got != robotProceed {
		t.Fatalf("outcome = %v, want proceed", got)
	}
	if b.clicks != 2 {
		t.Errorf("%d mouse events, want a press and a release", b.clicks)
	}
}

func TestCDPSolverWaitsForTheCheckboxToRender(t *testing.T) {
	polls := 0
	b := newFakeBrowser(t, evalScript("", func(expr string) (any, string) { return "success", "" }))
	b.onEval = func(expr string) (any, string) {
		switch {
		case strings.Contains(expr, "installed"):
			return "installed", ""
		case strings.Contains(expr, "SliderCaptcha"):
			polls++
			if polls < 3 {
				return "none", ""
			}
			return checkboxRect, ""
		}
		return "success", ""
	}
	r := solver(t, b.port)
	if got := r.cdpSolveRobot(context.Background()); got != robotProceed || b.clicks != 2 || polls < 3 {
		t.Fatalf("outcome %v, clicks %d, polls %d", got, b.clicks, polls)
	}
}

func TestCDPSolverReportsSlidersBeforeAndAfterTheClick(t *testing.T) {
	before := newFakeBrowser(t, evalScript("slider", func(string) (any, string) { return nil, "" }))
	if got := solver(t, before.port).cdpSolveRobot(context.Background()); got != robotSlider || before.clicks != 0 {
		t.Errorf("slider before: outcome %v, clicks %d (a human has to finish this one)", got, before.clicks)
	}

	for _, verdict := range []string{"slider", "error:captcha_failed"} {
		after := newFakeBrowser(t, evalScript(checkboxRect, func(expr string) (any, string) {
			if expr == "window.__wdtt_captcha" {
				return verdict, ""
			}
			return nil, ""
		}))
		if got := solver(t, after.port).cdpSolveRobot(context.Background()); got != robotSlider {
			t.Errorf("after click %q: outcome %v", verdict, got)
		}
	}

	// The slider can also show up without the interceptor noticing.
	late := 0
	b := newFakeBrowser(t, nil)
	b.onEval = func(expr string) (any, string) {
		switch {
		case strings.Contains(expr, "installed"):
			return "installed", ""
		case strings.Contains(expr, "SliderCaptcha"):
			late++
			if late == 1 {
				return checkboxRect, ""
			}
			return "slider", ""
		}
		return "pending", ""
	}
	if got := solver(t, b.port).cdpSolveRobot(context.Background()); got != robotSlider {
		t.Errorf("late slider: outcome %v", got)
	}
}

func TestCDPSolverProceedsWhenThereIsNothingToClickOrNothingConfirmed(t *testing.T) {
	none := newFakeBrowser(t, evalScript("none", func(string) (any, string) { return nil, "" }))
	if got := solver(t, none.port).cdpSolveRobot(context.Background()); got != robotProceed || none.clicks != 0 {
		t.Errorf("no checkbox: outcome %v, clicks %d", got, none.clicks)
	}
	quiet := newFakeBrowser(t, evalScript(checkboxRect, func(string) (any, string) { return "pending", "" }))
	if got := solver(t, quiet.port).cdpSolveRobot(context.Background()); got != robotProceed || quiet.clicks != 2 {
		t.Errorf("unconfirmed click: outcome %v, clicks %d", got, quiet.clicks)
	}
}

func TestCDPSolverFallsBackToTheBlindClickWhenTheBrowserCannotBeDriven(t *testing.T) {
	ctx := context.Background()
	if got := solver(t, 0).cdpSolveRobot(ctx); got != robotUnavailable {
		t.Errorf("CDP disabled: %v", got)
	}
	if got := solver(t, 1).cdpSolveRobot(ctx); got != robotUnavailable {
		t.Errorf("nothing listening: %v", got)
	}
	notVK := newFakeBrowser(t, evalScript("none", func(string) (any, string) { return nil, "" }))
	notVK.noTgt = true
	if got := solver(t, notVK.port).cdpSolveRobot(ctx); got != robotUnavailable {
		t.Errorf("no VK target: %v", got)
	}
	broken := newFakeBrowser(t, func(string) (any, string) { return nil, "Execution context was destroyed" })
	if got := solver(t, broken.port).cdpSolveRobot(ctx); got != robotUnavailable {
		t.Errorf("interceptor fails: %v", got)
	}
	noFind := newFakeBrowser(t, func(expr string) (any, string) {
		if strings.Contains(expr, "installed") {
			return "installed", ""
		}
		return nil, "navigated away"
	})
	if got := solver(t, noFind.port).cdpSolveRobot(ctx); got != robotUnavailable {
		t.Errorf("label lookup fails: %v", got)
	}
	badClick := newFakeBrowser(t, evalScript(checkboxRect, func(string) (any, string) { return nil, "" }))
	badClick.badClik = true
	if got := solver(t, badClick.port).cdpSolveRobot(ctx); got != robotUnavailable {
		t.Errorf("click refused: %v", got)
	}
	// A rect that cannot be parsed is not clicked blindly at some origin.
	badRect := newFakeBrowser(t, evalScript("0,0,0,0", func(string) (any, string) { return nil, "" }))
	if got := solver(t, badRect.port).cdpSolveRobot(ctx); got != robotUnavailable || badRect.clicks != 0 {
		t.Errorf("zero-size rect: outcome %v, clicks %d", got, badRect.clicks)
	}
}

func TestCDPEvalUnquotesStringsAndKeepsOtherValuesAsText(t *testing.T) {
	values := map[string]any{"s": "text", "n": 42, "b": true, "z": nil}
	b := newFakeBrowser(t, func(expr string) (any, string) { return values[expr], "" })
	r := solver(t, b.port)
	conn, err := r.dialCaptchaTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.close()
	for expr, want := range map[string]string{"s": "text", "n": "42", "b": "true", "z": "null"} {
		got, err := conn.eval(context.Background(), expr)
		if err != nil || got != want {
			t.Errorf("eval(%q) = %q, %v; want %q", expr, got, err, want)
		}
	}
}
