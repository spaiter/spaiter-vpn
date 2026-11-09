package webapp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The browser path. Not every Telegram client hosts Mini Apps -- Telegram X
// has no WebView host at all, so its menu button does nothing -- and a desktop
// browser is sometimes simply more convenient. For those, the bot hands out a
// one-time login link: the same page, opened outside Telegram, exchanges the
// link for a cookie session and then talks to the same API. The link is the
// credential, so it is short-lived, single-use and bound to one user; the
// session it opens is held in memory and dies with the process.

const (
	loginTTL      = 10 * time.Minute
	sessionTTL    = 12 * time.Hour
	sessionCookie = "spaiter_vpn_app"
	// loginParam is the query parameter the page looks for.
	loginParam = "login"
	// requestedWith must accompany every cookie-authenticated API call. A
	// browser will not attach a custom header cross-origin without a
	// preflight, and the API answers no preflight, so this is the CSRF guard
	// alongside SameSite.
	requestedWith = "spaiter-vpn"
)

// loginKey derives the signing key from the bot token, so a link is tied to
// this bot without a second secret to manage.
func loginKey(token string) []byte {
	sum := sha256.Sum256([]byte("spaiter-vpn webapp login\n" + token))
	return sum[:]
}

// LoginLink mints a link that opens the app for one user in a browser.
func (s *Server) LoginLink(uid int64, now time.Time) (string, error) {
	base := URL(s.cfg)
	if base == "" {
		return "", errors.New("webapp: no public URL")
	}
	payload := make([]byte, 8+8+16)
	binary.BigEndian.PutUint64(payload[0:], uint64(uid))
	binary.BigEndian.PutUint64(payload[8:], uint64(now.Add(loginTTL).Unix()))
	if _, err := rand.Read(payload[16:]); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, loginKey(s.token))
	mac.Write(payload)
	token := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	return base + "?" + loginParam + "=" + url.QueryEscape(token), nil
}

// consumeLogin verifies a login token and burns its nonce.
func (s *Server) consumeLogin(token string, now time.Time) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 8+8+16+sha256.Size {
		return 0, errors.New("malformed login link")
	}
	payload, signature := raw[:32], raw[32:]
	mac := hmac.New(sha256.New, loginKey(s.token))
	mac.Write(payload)
	if subtle.ConstantTimeCompare(mac.Sum(nil), signature) != 1 {
		return 0, errors.New("login link is not from this bot")
	}
	if now.Unix() > int64(binary.BigEndian.Uint64(payload[8:16])) {
		return 0, errors.New("login link has expired, ask the bot for a new one")
	}
	if !s.sessions.burn(hex.EncodeToString(payload[16:32]), now) {
		return 0, errors.New("login link was already used, ask the bot for a new one")
	}
	return int64(binary.BigEndian.Uint64(payload[0:8])), nil
}

// sessionStore holds browser sessions and the nonces of used login links.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]browserSession
	used     map[string]time.Time
}

type browserSession struct {
	uid     int64
	expires time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]browserSession{}, used: map[string]time.Time{}}
}

// burn records a nonce; false when it was seen before.
func (st *sessionStore) burn(nonce string, now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, seen := range st.used {
		if now.Sub(seen) > loginTTL {
			delete(st.used, k)
		}
	}
	if _, seen := st.used[nonce]; seen {
		return false
	}
	st.used[nonce] = now
	return true
}

func (st *sessionStore) open(uid int64, now time.Time) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	id := hex.EncodeToString(raw)
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, v := range st.sessions {
		if now.After(v.expires) {
			delete(st.sessions, k)
		}
	}
	st.sessions[id] = browserSession{uid: uid, expires: now.Add(sessionTTL)}
	return id
}

func (st *sessionStore) lookup(id string, now time.Time) (int64, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.sessions[id]
	if !ok || now.After(v.expires) {
		return 0, false
	}
	return v.uid, true
}

func (st *sessionStore) close(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.sessions, id)
}

// --- handlers ---

// session exchanges a login link for a cookie. The page calls it once, with
// the token it found in its own URL.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login string `json:"login"`
	}
	if err := readJSON(r, &req); err != nil || req.Login == "" {
		jsonError(w, http.StatusBadRequest, "login token is required")
		return
	}
	uid, err := s.consumeLogin(req.Login, s.now())
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	id := s.sessions.open(uid, s.now())
	if id == "" {
		jsonError(w, http.StatusInternalServerError, "could not open a session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: Prefix,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionTTL / time.Second),
	})
	writeJSON(w, map[string]any{"ok": true})
}

// logout ends a browser session.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.close(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: Prefix, MaxAge: -1, HttpOnly: true})
	writeJSON(w, map[string]any{"ok": true})
}

// fromSession authenticates a request by its cookie, when it carries the
// anti-CSRF header. Only the id is known from a session; the name shown is
// whatever the registry already has.
func (s *Server) fromSession(r *http.Request) (User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || r.Header.Get("X-Requested-With") != requestedWith {
		return User{}, false
	}
	uid, ok := s.sessions.lookup(c.Value, s.now())
	if !ok {
		return User{}, false
	}
	return User{ID: uid}, true
}

// isHTTPS tells whether the request arrived over TLS, directly or through the
// tunnel, which says so in the usual header.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
