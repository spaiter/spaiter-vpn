package vk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// relogin_captcha.go drives the VK Smart Captcha "I'm not a robot" checkbox
// through the app's embedded QtWebEngine over the Chrome DevTools Protocol
// (CDP), instead of clicking blindly at fixed screen coordinates. It mirrors
// what the public qWDTT/Rawline client does in its own WebView: install a
// fetch/XHR interceptor that catches the captchaNotRobot.check response, find
// the checkbox label, click a random point inside it with a trusted CDP mouse
// event, then confirm a success_token (or detect a slider escalation).
//
// The solver only passes the checkbox; a slider/image captcha still needs a
// human, but it is detected immediately so the operator is called to VNC
// rather than the flow stalling on the code wait. The CDP endpoint is enabled
// by launching the app with --remote-debugging-port (see init / mergeChromiumFlags).

// mergeChromiumFlags returns existing QTWEBENGINE_CHROMIUM_FLAGS with add
// appended, unless a flag with the same key (text before '=') is already there.
// Order is preserved and the result stays space-separated.
func mergeChromiumFlags(existing, add string) string {
	addKey := add
	if i := strings.IndexByte(add, '='); i >= 0 {
		addKey = add[:i]
	}
	for _, f := range strings.Fields(existing) {
		key := f
		if i := strings.IndexByte(f, '='); i >= 0 {
			key = f[:i]
		}
		if key == addKey {
			return existing // already set; do not duplicate or override
		}
	}
	if strings.TrimSpace(existing) == "" {
		return add
	}
	return strings.TrimSpace(existing) + " " + add
}

// cdpTarget is one entry from the /json target list.
type cdpTarget struct {
	Type                 string `json:"type"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// pickCaptchaTarget chooses the inspectable target most likely to hold the VK
// ID captcha. A not_robot/captcha URL wins; otherwise any id.vk page is taken.
// It returns false when no VK ID target with a debugger socket is present.
func pickCaptchaTarget(targets []cdpTarget) (cdpTarget, bool) {
	var vkFallback cdpTarget
	haveFallback := false
	for _, t := range targets {
		if t.WebSocketDebuggerURL == "" {
			continue
		}
		u := strings.ToLower(t.URL)
		if strings.Contains(u, "not_robot") || strings.Contains(u, "captcha") {
			return t, true
		}
		if (strings.Contains(u, "id.vk.") || strings.Contains(u, "login.vk.")) && !haveFallback {
			vkFallback = t
			haveFallback = true
		}
	}
	return vkFallback, haveFallback
}

// captchaInterceptorJS hooks fetch and XHR so the captchaNotRobot.check result
// is stashed on window.__wdtt_captcha for the Go side to poll: "success" once a
// success_token is returned, "slider" if VK asks for a slider, "error:<...>"
// otherwise. Installed idempotently.
const captchaInterceptorJS = `
(function () {
  if (window.__wdtt_interceptor) return 'already';
  window.__wdtt_interceptor = true;
  window.__wdtt_captcha = 'pending';
  function handle(data) {
    try {
      if (data && data.response && data.response.success_token) {
        window.__wdtt_captcha = 'success';
      } else if (data && data.response && data.response.show_captcha_type === 'slider') {
        window.__wdtt_captcha = 'slider';
      } else if (data && data.error) {
        window.__wdtt_captcha = 'error:' + JSON.stringify(data.error);
      }
    } catch (e) {}
  }
  var of = window.fetch;
  window.fetch = function () {
    var url = arguments[0] || '';
    var p = of.apply(this, arguments);
    if (typeof url === 'string' && url.indexOf('captchaNotRobot.check') >= 0) {
      p.then(function (r) { r.clone().json().then(handle).catch(function () {}); });
    }
    return p;
  };
  var oo = XMLHttpRequest.prototype.open, os = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this.__wdtt_url = u; return oo.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    var x = this;
    if (x.__wdtt_url && String(x.__wdtt_url).indexOf('captchaNotRobot.check') >= 0) {
      x.addEventListener('load', function () { try { handle(JSON.parse(x.responseText)); } catch (e) {} });
    }
    return os.apply(this, arguments);
  };
  return 'installed';
})();
`

// captchaFindLabelJS returns "slider" if a slider/kaleidoscope captcha is up,
// "none" if no checkbox is present yet, or "left,top,width,height" for the
// clickable "I'm not a robot" label. Selectors track the VK Smart Captcha DOM.
const captchaFindLabelJS = `
(function () {
  var slider = document.querySelector('[class*="SliderCaptcha"],[class*="Kaleidoscope"],.vkc__SliderCaptcha-module__description,.vkc__KaleidoscopeScreen-module__captchaId,.vkc__SwipeButton-module__track');
  if (slider) return 'slider';
  var el = document.querySelector('label.vkc__Checkbox-module__Checkbox') ||
           document.querySelector('label[for="not-robot-captcha-checkbox"]') ||
           document.getElementById('not-robot-captcha-checkbox');
  if (!el) return 'none';
  var r = el.getBoundingClientRect();
  var s = window.getComputedStyle(el);
  if (r.width < 5 || r.height < 5 || s.display === 'none' || s.visibility === 'hidden') return 'none';
  return r.left + ',' + r.top + ',' + r.width + ',' + r.height;
})();
`

// cdpSolveRobot is the default solveRobot: it drives the checkbox over CDP and
// classifies the outcome. Any browser-side problem returns robotUnavailable so
// the caller does the legacy blind click rather than failing the relogin.
func (r *Relogin) cdpSolveRobot(ctx context.Context) robotOutcome {
	if r.Cfg.DebugPort <= 0 {
		return robotUnavailable // CDP disabled: caller does the blind click
	}
	conn, err := r.dialCaptchaTarget(ctx)
	if err != nil {
		r.Log.Warn("captcha: no CDP target", "err", err)
		return robotUnavailable
	}
	defer conn.close()

	if _, err := conn.eval(ctx, captchaInterceptorJS); err != nil {
		r.Log.Warn("captcha: interceptor install failed", "err", err)
		return robotUnavailable
	}

	// Wait briefly for the checkbox to render; re-check for a slider each time.
	var rect string
	deadline := r.Now().Add(4 * time.Second)
	for {
		v, err := conn.eval(ctx, captchaFindLabelJS)
		if err != nil {
			r.Log.Warn("captcha: find label failed", "err", err)
			return robotUnavailable
		}
		switch {
		case v == "slider":
			r.Log.Info("captcha: slider escalation before click")
			return robotSlider
		case v != "none" && strings.Count(v, ",") == 3:
			rect = v
		}
		if rect != "" || !r.Now().Before(deadline) {
			break
		}
		r.sleep(400 * time.Millisecond)
	}
	if rect == "" {
		// No checkbox appeared: either there was no captcha, or the DOM changed.
		// Proceed; the flow either continues to the code or stalls and the
		// operator takes over. This matches the old "click if present" intent.
		r.Log.Info("captcha: no checkbox present, proceeding")
		return robotProceed
	}

	x, y, ok := randomPointInRect(rect, rand.Float64)
	if !ok {
		return robotUnavailable
	}
	if err := conn.click(ctx, x, y); err != nil {
		r.Log.Warn("captcha: click dispatch failed", "err", err)
		return robotUnavailable
	}
	r.Log.Info("captcha: clicked checkbox", "x", int(x), "y", int(y))

	// Confirm the pass: poll the interceptor result and keep watching for a
	// post-click slider. A trusted click that we cannot confirm is still treated
	// as proceed, since the click itself most likely advanced the page.
	deadline = r.Now().Add(r.Cfg.CaptchaWait)
	for r.Now().Before(deadline) {
		v, err := conn.eval(ctx, "window.__wdtt_captcha")
		if err == nil {
			switch {
			case v == "success":
				r.Log.Info("captcha: success_token observed")
				return robotProceed
			case v == "slider" || strings.HasPrefix(v, "error:"):
				r.Log.Info("captcha: escalated after click", "result", v)
				return robotSlider
			}
		}
		if sv, err := conn.eval(ctx, captchaFindLabelJS); err == nil && sv == "slider" {
			return robotSlider
		}
		r.sleep(500 * time.Millisecond)
	}
	r.Log.Info("captcha: no confirmation seen; proceeding on the trusted click")
	return robotProceed
}

// randomPointInRect parses "left,top,width,height" and picks a point inside the
// label the way a finger lands: 15-85% across, 25-75% down. ok is false on a
// malformed rect.
func randomPointInRect(rect string, f func() float64) (x, y float64, ok bool) {
	parts := strings.Split(rect, ",")
	if len(parts) != 4 {
		return 0, 0, false
	}
	var v [4]float64
	for i := range parts {
		n, err := strconv.ParseFloat(strings.TrimSpace(parts[i]), 64)
		if err != nil {
			return 0, 0, false
		}
		v[i] = n
	}
	left, top, w, h := v[0], v[1], v[2], v[3]
	if w < 1 || h < 1 {
		return 0, 0, false
	}
	x = left + w*(0.15+f()*0.70)
	y = top + h*(0.25+f()*0.50)
	return x, y, true
}

// --- minimal CDP connection ------------------------------------------------

type cdpConn struct {
	ws *websocket.Conn
	id int
}

// dialCaptchaTarget lists the debugger targets, picks the VK ID one and opens
// its websocket.
func (r *Relogin) dialCaptchaTarget(ctx context.Context) (*cdpConn, error) {
	base := fmt.Sprintf("http://127.0.0.1:%d", r.Cfg.DebugPort)
	cl := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var targets []cdpTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return nil, err
	}
	t, ok := pickCaptchaTarget(targets)
	if !ok {
		return nil, errors.New("no VK ID debugger target")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dialCtx, t.WebSocketDebuggerURL, nil)
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(-1)
	return &cdpConn{ws: ws}, nil
}

func (c *cdpConn) close() { _ = c.ws.Close(websocket.StatusNormalClosure, "") }

// send issues a CDP command and returns the matching result object, skipping
// event messages (which carry no "id").
func (c *cdpConn) send(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	c.id++
	id := c.id
	cmd := map[string]any{"id": id, "method": method}
	if params != nil {
		cmd["params"] = params
	}
	raw, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	if err := c.ws.Write(ctx, websocket.MessageText, raw); err != nil {
		return nil, err
	}
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return nil, err
		}
		var msg struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &msg) != nil || msg.ID != id {
			continue // an event or an unrelated reply
		}
		if msg.Error != nil {
			return nil, errors.New(msg.Error.Message)
		}
		return msg.Result, nil
	}
}

// eval runs expr via Runtime.evaluate and returns its string value (numbers and
// bools are returned as their JSON text).
func (c *cdpConn) eval(ctx context.Context, expr string) (string, error) {
	res, err := c.send(ctx, "Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(out.Result.Value))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var unq string
		if json.Unmarshal(out.Result.Value, &unq) == nil {
			return unq, nil
		}
	}
	return s, nil
}

// click dispatches a trusted left press+release at viewport CSS coordinates.
func (c *cdpConn) click(ctx context.Context, x, y float64) error {
	for _, typ := range []string{"mousePressed", "mouseReleased"} {
		if _, err := c.send(ctx, "Input.dispatchMouseEvent", map[string]any{
			"type":       typ,
			"x":          x,
			"y":          y,
			"button":     "left",
			"buttons":    1,
			"clickCount": 1,
		}); err != nil {
			return err
		}
	}
	return nil
}
