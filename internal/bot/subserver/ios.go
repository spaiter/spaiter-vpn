package subserver

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
)

// iosAppName is the profile name the iOS app gives the imported subscription.
const iosAppName = "Spaiter VPN"

// IOS serves /ios/<token>: a page that hands the subscription to the iOS app.
//
// Telegram opens only http(s) links from a button, so the bot cannot link the
// app's spaiter:// scheme directly; this page is the step in between. base is
// the https origin the app is told to poll ("https://sub.example.com"). It
// has to be https whatever host the page itself was reached on, because the
// app refuses anything else, so it is configured rather than taken from the
// request. An empty base leaves the page unserved.
func (s *Server) IOS(base string) *Server {
	s.iosBase = strings.TrimSuffix(base, "/")
	return s
}

// iosLinks are the two links on the page for one token.
func (s *Server) iosLinks(token string) (subscription, app string) {
	subscription = s.iosBase + "/sub/" + url.PathEscape(token) +
		"?format=full&platform=" + clientcfg.PlatformIOS
	// Built by hand rather than with url.Values: Encode writes a space as
	// "+", which the app's URLComponents keeps as a literal plus.
	app = "spaiter://import?url=" + url.QueryEscape(subscription) +
		"&name=" + url.PathEscape(iosAppName)
	return subscription, app
}

func (s *Server) iosPage(w http.ResponseWriter, r *http.Request) {
	if !allowed(w, r) {
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/ios/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	// The same answer as /sub/ for a token without a cache: the page must not
	// tell a guessed token from a real one any more than the feed does.
	if _, found, err := s.store.BundleCache(token); err != nil || !found {
		if err != nil {
			s.log.Error("reading a bundle cache failed", "error", err)
		}
		http.NotFound(w, r)
		return
	}

	subscription, app := s.iosLinks(token)
	nonce, err := newNonce()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var page bytes.Buffer
	if err := iosTemplate.Execute(&page, iosPageData{
		// html/template rewrites a non-http scheme in href to "#ZgotmplZ";
		// this one is ours and built above from an escaped token.
		AppURL:          template.URL(app),
		SubscriptionURL: subscription,
		Nonce:           nonce,
	}); err != nil {
		s.log.Error("rendering the iOS page failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// The URL carries the token: no cache may keep the page, and no link
	// followed from it may pass the address on.
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "+
		"script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_, _ = w.Write(page.Bytes())
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type iosPageData struct {
	AppURL          template.URL
	SubscriptionURL string
	Nonce           string
}

var iosTemplate = template.Must(template.New("ios").Parse(`<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Spaiter VPN для iPhone</title>
<style>
:root { color-scheme: light dark; --bg: #f2f2f7; --card: #fff; --text: #1c1c1e; --muted: #6c6c70; --accent: #0a84ff; }
@media (prefers-color-scheme: dark) { :root { --bg: #000; --card: #1c1c1e; --text: #f2f2f7; --muted: #98989f; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 17px/1.45 -apple-system, system-ui, sans-serif; }
main { max-width: 480px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 28px; margin: 0 0 8px; }
h2 { font-size: 17px; margin: 32px 0 8px; }
p, li { color: var(--muted); }
.open { display: block; margin: 24px 0 0; padding: 16px; border-radius: 14px; background: var(--accent); color: #fff; text-align: center; text-decoration: none; font-weight: 600; }
.copy { width: 100%; margin-top: 12px; padding: 14px; border: 0; border-radius: 14px; background: var(--card); color: var(--accent); font: inherit; font-weight: 600; }
ol { padding-left: 20px; }
#copied { text-align: center; }
</style>
</head>
<body>
<main>
<h1>Spaiter VPN для iPhone</h1>
<p>Нажми кнопку: приложение откроется и само добавит подписку со всеми методами. Подписка будет обновляться сама.</p>
<a class="open" href="{{.AppURL}}">Открыть в Spaiter VPN</a>
<h2>Не открывается?</h2>
<ol>
<li>Проверь, что приложение Spaiter VPN установлено.</li>
<li>Если страница открылась внутри Telegram, нажми меню (•••) → «Открыть в Safari» и нажми кнопку ещё раз.</li>
<li>Или скопируй ссылку и в приложении нажми «Вставить».</li>
</ol>
<button class="copy" id="copy" type="button">Скопировать ссылку подписки</button>
<p id="copied" hidden>Скопировано</p>
</main>
<script nonce="{{.Nonce}}">
document.getElementById("copy").addEventListener("click", async function () {
  var link = {{.SubscriptionURL}};
  try {
    await navigator.clipboard.writeText(link);
    document.getElementById("copied").hidden = false;
  } catch (e) {
    window.prompt("Скопируй ссылку:", link);
  }
});
</script>
</body>
</html>
`))
