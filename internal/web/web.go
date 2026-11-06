// Package web is the browser front end of the local control plane: the second
// client of the control socket, beside the Telegram bot. It holds no deployment
// logic and no privilege of its own. Every change is a typed control request,
// shown as the daemon's plan and committed only by the ticket an operator
// confirmed, exactly as from the bot or the CLI.
//
// Access is by one-time login links signed with a key file the operator
// creates. A link is single-use and short-lived; the session it opens lives in
// memory, is bound to an HttpOnly, SameSite=Strict cookie, and every form
// carries that session's CSRF token.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/control"
)

// Control is the part of control.Client the server uses.
type Control interface {
	Do(ctx context.Context, request control.Request) (control.Response, error)
}

// KeyLen is the login-link signing key's size.
const KeyLen = 32

// LoadKey reads a signing key. It must not be readable by others: whoever can
// read it can mint a login link.
func LoadKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("%s is accessible to others (mode %04o); it signs login links", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != KeyLen {
		return nil, fmt.Errorf("%s does not hold a %d-byte hex key", path, KeyLen)
	}
	return key, nil
}

// NewKey returns a fresh key in the file format.
func NewKey() (string, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key) + "\n", nil
}

// LoginToken signs a token valid until expires. The nonce makes it single-use.
func LoginToken(key []byte, expires time.Time) (string, error) {
	payload := make([]byte, 8+16)
	binary.BigEndian.PutUint64(payload, uint64(expires.Unix()))
	if _, err := rand.Read(payload[8:]); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...)), nil
}

// verifyToken checks a token's signature and expiry and returns its nonce.
func verifyToken(key []byte, token string, now time.Time) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 8+16+sha256.Size {
		return "", errors.New("malformed login link")
	}
	payload, signature := raw[:24], raw[24:]
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if subtle.ConstantTimeCompare(mac.Sum(nil), signature) != 1 {
		return "", errors.New("login link is not signed by this server's key")
	}
	if now.Unix() > int64(binary.BigEndian.Uint64(payload)) {
		return "", errors.New("login link has expired")
	}
	return hex.EncodeToString(payload[8:]), nil
}

type session struct {
	csrf    string
	expires time.Time
}

// Server is the HTTP front end.
type Server struct {
	Control Control
	Key     []byte
	// Secure marks the session cookie Secure; set it whenever the server is
	// reached over HTTPS, which is every case except a loopback tunnel.
	Secure     bool
	SessionTTL time.Duration
	Now        func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
	used     map[string]time.Time
}

const cookieName = "spaiter_vpn_session"

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler returns the server's routes.
func (s *Server) Handler() http.Handler {
	if s.SessionTTL == 0 {
		s.SessionTTL = 8 * time.Hour
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions, s.used = map[string]*session{}, map[string]time.Time{}
	}
	s.mu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /{$}", s.authed(s.home))
	mux.HandleFunc("POST /prepare", s.authed(s.csrf(s.prepare)))
	mux.HandleFunc("POST /commit", s.authed(s.csrf(s.commit)))
	mux.HandleFunc("POST /cancel", s.authed(s.csrf(s.cancel)))
	mux.HandleFunc("POST /logout", s.authed(s.csrf(s.logout)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func randomID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	nonce, err := verifyToken(s.Key, r.URL.Query().Get("token"), s.now())
	if err == nil {
		s.mu.Lock()
		s.expireLocked()
		if _, seen := s.used[nonce]; seen {
			err = errors.New("login link was already used")
		} else {
			// Remembered past any token's lifetime, which LoginLink caps.
			s.used[nonce] = s.now().Add(25 * time.Hour)
		}
		s.mu.Unlock()
	}
	if err != nil {
		render(w, http.StatusForbidden, pageMessage("Вход не выполнен", err.Error()+". Запросите новую ссылку: `spaiter-vpn web login-link` на сервере или /weblogin в боте."))
		return
	}
	id := randomID()
	s.mu.Lock()
	s.sessions[id] = &session{csrf: randomID(), expires: s.now().Add(s.SessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.SessionTTL.Seconds()),
	})
	// Redirect, so the token leaves the address bar and the history.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) expireLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.expires) {
			delete(s.sessions, id)
		}
	}
	for nonce, until := range s.used {
		if now.After(until) {
			delete(s.used, nonce)
		}
	}
}

type ctxKey struct{}

func (s *Server) authed(next func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		var sess *session
		if err == nil {
			s.mu.Lock()
			s.expireLocked()
			sess = s.sessions[cookie.Value]
			s.mu.Unlock()
		}
		if sess == nil {
			render(w, http.StatusUnauthorized, pageMessage("Нужен вход", "Откройте одноразовую ссылку: `spaiter-vpn web login-link` на сервере или /weblogin в боте."))
			return
		}
		next(w, r, sess)
	}
}

// csrf requires the session's token in the form and a same-origin request.
// SameSite=Strict already keeps the cookie off cross-site requests; this is
// the second, independent lock.
func (s *Server) csrf(next func(http.ResponseWriter, *http.Request, *session)) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		if origin := r.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Host != r.Host {
				render(w, http.StatusForbidden, pageMessage("Отклонено", "запрос пришёл с другого сайта"))
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(sess.csrf)) != 1 {
			render(w, http.StatusForbidden, pageMessage("Отклонено", "форма устарела или подделана; откройте страницу заново"))
			return
		}
		next(w, r, sess)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ *session) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode})
	render(w, http.StatusOK, pageMessage("Выход", "Сессия закрыта."))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, sess *session) {
	data := homeData{CSRF: sess.csrf}
	if response, err := s.Control.Do(r.Context(), control.Request{Operation: control.OpStatus}); err != nil || !response.OK {
		data.Error = controlError(response, err)
	} else {
		_ = json.Unmarshal(response.Result, &data.Status)
	}
	if response, err := s.Control.Do(r.Context(), control.Request{Operation: control.OpGenerations}); err == nil && response.OK {
		_ = json.Unmarshal(response.Result, &data.Generations)
	}
	render(w, http.StatusOK, pageHome(data))
}

// changeFromForm builds a typed change from the one form that was submitted.
func changeFromForm(form url.Values) (control.Change, error) {
	switch form.Get("kind") {
	case string(control.ChangeSettings):
		change := control.Change{Kind: control.ChangeSettings}
		if protocol, port := strings.TrimSpace(form.Get("protocol")), strings.TrimSpace(form.Get("port")); protocol != "" && port != "" {
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil || n == 0 {
				return control.Change{}, fmt.Errorf("порт %q не число от 1 до 65535", port)
			}
			change.Ports = map[string]uint16{protocol: uint16(n)}
		}
		if protocol := strings.TrimSpace(form.Get("enable")); protocol != "" {
			change.Enable = []string{protocol}
		}
		if protocol := strings.TrimSpace(form.Get("disable")); protocol != "" {
			change.Disable = []string{protocol}
		}
		return change, change.Validate()
	case string(control.ChangeImage):
		change := control.Change{Kind: control.ChangeImage, Image: strings.TrimSpace(form.Get("image"))}
		return change, change.Validate()
	case string(control.ChangeRotate):
		var users []string
		for _, name := range strings.FieldsFunc(form.Get("users"), func(r rune) bool { return r == ',' || r == ' ' }) {
			users = append(users, name)
		}
		change := control.Change{Kind: control.ChangeRotate, Users: users}
		return change, change.Validate()
	case string(control.ChangeRollback):
		change := control.Change{Kind: control.ChangeRollback}
		if generation := strings.TrimSpace(form.Get("generation")); generation != "" {
			n, err := strconv.ParseUint(generation, 10, 64)
			if err != nil {
				return control.Change{}, fmt.Errorf("поколение %q не число", generation)
			}
			change.Generation = n
		}
		return change, change.Validate()
	}
	return control.Change{}, fmt.Errorf("неизвестный вид изменения")
}

func (s *Server) prepare(w http.ResponseWriter, r *http.Request, sess *session) {
	change, err := changeFromForm(r.PostForm)
	if err != nil {
		render(w, http.StatusBadRequest, pageMessage("Изменение не принято", err.Error()))
		return
	}
	response, err := s.Control.Do(r.Context(), control.Request{Operation: control.OpPrepare, Change: &change})
	if err != nil || !response.OK {
		render(w, http.StatusConflict, pageResult("План не построен", controlError(response, err), response.Output))
		return
	}
	var ticket struct {
		ID   string          `json:"id"`
		Plan json.RawMessage `json:"plan"`
	}
	if err := json.Unmarshal(response.Result, &ticket); err != nil || ticket.ID == "" {
		render(w, http.StatusBadGateway, pageMessage("План не построен", "демон не вернул тикет"))
		return
	}
	render(w, http.StatusOK, pagePlan(planData{CSRF: sess.csrf, Summary: change.Summary(), Ticket: ticket.ID, Plan: parsePlan(ticket.Plan)}))
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request, _ *session) {
	ticket := r.PostForm.Get("ticket")
	response, err := s.Control.Do(r.Context(), control.Request{Operation: control.OpCommit, Ticket: ticket})
	if err != nil || !response.OK {
		render(w, http.StatusConflict, pageResult("Не применено", controlError(response, err), response.Output))
		return
	}
	var result struct {
		Transaction string `json:"Transaction"`
	}
	_ = json.Unmarshal(response.Result, &result)
	render(w, http.StatusOK, pageResult("Применено", "транзакция "+result.Transaction, response.Output))
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request, _ *session) {
	_, _ = s.Control.Do(r.Context(), control.Request{Operation: control.OpCancel, Ticket: r.PostForm.Get("ticket")})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func controlError(response control.Response, err error) string {
	if err != nil {
		return err.Error()
	}
	return response.Error
}
