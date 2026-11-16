package subserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func iosServer(store *fakeStore) http.Handler {
	return newServer(store).IOS("https://sub.example.org/").Handler()
}

func TestIOSPageLinksTheAppToTheFullConfig(t *testing.T) {
	store := &fakeStore{bundles: map[string][]byte{"tok-1": []byte(`{}`)}}
	resp := get(t, iosServer(store), "/ios/tok-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)

	const subscription = "https://sub.example.org/sub/tok-1?format=full&platform=ios"
	app := "spaiter://import?url=" + url.QueryEscape(subscription) + "&amp;name=Spaiter%20VPN"
	if !strings.Contains(body, `href="`+app+`"`) {
		t.Errorf("the app link is missing or mangled (html/template turns a foreign scheme into #ZgotmplZ):\n%s", body)
	}
	if strings.Contains(body, "ZgotmplZ") {
		t.Error("html/template refused a URL on the page")
	}
	// In the script the link is a JS string literal, escaped by the template.
	if !strings.Contains(body, `"https://sub.example.org/sub/tok-1?format=full\u0026platform=ios"`) {
		t.Errorf("the copy button lost the subscription URL:\n%s", body)
	}

	h := resp.Header
	if !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q", h.Get("Content-Type"))
	}
	for name, want := range map[string]string{
		"Cache-Control":   "no-store",
		"Referrer-Policy": "no-referrer",
		"X-Robots-Tag":    "noindex",
	} {
		if h.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, h.Get(name), want)
		}
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'nonce-") {
		t.Errorf("CSP = %q", csp)
	}
	nonce := csp[strings.Index(csp, "'nonce-")+len("'nonce-"):]
	nonce = nonce[:strings.Index(nonce, "'")]
	if !strings.Contains(body, `<script nonce="`+nonce+`">`) {
		t.Error("the script does not carry the CSP nonce, the copy button would be dead")
	}
}

func TestIOSPageAnswersLikeTheFeedForUnknownTokens(t *testing.T) {
	store := &fakeStore{bundles: map[string][]byte{"tok-1": []byte(`{}`)}}
	h := iosServer(store)
	for _, path := range []string{"/ios/nope", "/ios/", "/ios/tok-1/x"} {
		if resp := get(t, h, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
	store.err = io.ErrUnexpectedEOF
	if resp := get(t, h, "/ios/tok-1"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unreadable cache: status = %d, want 404", resp.StatusCode)
	}
}

func TestIOSPageIsAbsentWithoutAnHTTPSBase(t *testing.T) {
	store := &fakeStore{bundles: map[string][]byte{"tok-1": []byte(`{}`)}}
	resp := get(t, newServer(store).Handler(), "/ios/tok-1")
	raw, _ := io.ReadAll(resp.Body)
	// Falls through to the health answer, as any unknown path does.
	if strings.Contains(string(raw), "spaiter://") {
		t.Error("the page was served without a configured https base")
	}
}

func TestIOSPageRefusesWrites(t *testing.T) {
	store := &fakeStore{bundles: map[string][]byte{"tok-1": []byte(`{}`)}}
	rec := httptest.NewRecorder()
	iosServer(store).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ios/tok-1", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status = %d", rec.Code)
	}
}
