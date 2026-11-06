// Package webapp is the Telegram Mini App: the bot's self-service surface as a
// page inside Telegram instead of a chain of inline keyboards.
//
// It is served by the same process and the same port as the subscription
// server, under /app/, so it is reachable wherever /sub/ is -- through the
// tunnel the subscriptions already use -- and needs no new front door, no
// certificate and no login. Telegram signs what it passes to the page, the
// page passes that on with every request, and the signature is checked each
// time. Everything a request can do is what the same user could do through the
// bot's buttons, through the same service, under the same access check.
package webapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

//go:embed static/index.html
var static embed.FS

// Methods is the slice of the bot's service the app drives. An interface so
// the handlers can be exercised against a fake, and so the list of what the
// page can reach is written down in one place.
type Methods interface {
	UserInbounds(ctx context.Context) ([]manage.InboundRef, error)
	OfferedEndpoints(ctx context.Context) ([]clientcfg.Endpoint, error)
	Link(ctx context.Context, tag, uid string) (string, error)
	JSONConfig(ctx context.Context, tag, uid string) ([]byte, error)
	AWGConf(ctx context.Context, tag, uid string) (string, error)
	WARPChainConfig(ctx context.Context, uid string) ([]byte, error)
	WDTTConfig(ctx context.Context, uid string) ([]byte, error)
	Bundle(ctx context.Context, uid string, provision bool) ([]byte, error)
	Stats(ctx context.Context, uid string) (manage.UserStat, bool, error)
	AllStats(ctx context.Context) ([]manage.UserStat, error)
	Accounts(ctx context.Context) (map[string][]string, error)
}

// Access is the whitelist as the app needs it.
type Access interface {
	IsAdmin(uid int64) bool
	IsAllowed(uid int64) bool
	Register(user state.User)
	RequestAccess(uid int64)
	Approve(uid int64) error
	Reject(uid int64) error
	Revoke(uid int64) error
	Pending() []int64
	Whitelist() []int64
	DisplayName(uid int64) string
}

// Store is the state the app reads and writes: the subscription registry and
// its cache.
type Store interface {
	SubscriptionToken(uid string) (string, error)
	SetBundleCache(token string, bundle []byte) error
	UpdateSubscriptions(fn func(state.Subscriptions) error) error
}

// Server is the Mini App.
type Server struct {
	cfg    botcfg.Config
	svc    Methods
	access Access
	store  Store
	token  string
	log    *slog.Logger
	now    func() time.Time

	// OnAccessRequest tells the admins somebody asked, the same way the bot
	// does when the request comes through a button. Optional.
	OnAccessRequest func(ctx context.Context, uid int64)
	// Tell sends a user a courtesy notice -- the verdict on their request.
	// Optional.
	Tell func(ctx context.Context, uid int64, text string)

	files *ticketStore
}

// New builds the app over the bot's collaborators. token is the Telegram bot
// token, which is what Telegram signed the init data with.
func New(cfg botcfg.Config, svc Methods, access Access, store Store, token string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg: cfg, svc: svc, access: access, store: store, token: token, log: log,
		now:   time.Now,
		files: newTicketStore(5 * time.Minute),
	}
}

// Prefix is where the app is mounted. The page, its API and the file tickets
// all live under it.
const Prefix = "/app/"

// URL is the public address of the app for a deployment, or "" when it has
// none. Explicit configuration wins; otherwise the Cloudflare-fronted
// subscription host serves it, because that host already reaches this port
// over HTTPS and Telegram accepts nothing less.
func URL(cfg botcfg.Config) string {
	if cfg.WebApp.URL != "" {
		return cfg.WebApp.URL
	}
	if cfg.WebApp.Disabled {
		return ""
	}
	if host := cfg.Subscription.HostCF; host != "" {
		return "https://" + host + Prefix
	}
	return ""
}

// Handler routes the app. Mount it at Prefix.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Prefix+"{$}", s.index)
	mux.HandleFunc("GET "+Prefix+"api/me", s.authed(s.me))
	mux.HandleFunc("GET "+Prefix+"api/methods", s.authed(s.allowed(s.methods)))
	mux.HandleFunc("POST "+Prefix+"api/issue", s.authed(s.allowed(s.issue)))
	mux.HandleFunc("POST "+Prefix+"api/subscription", s.authed(s.allowed(s.subscription)))
	mux.HandleFunc("POST "+Prefix+"api/qr", s.authed(s.allowed(s.qr)))
	mux.HandleFunc("POST "+Prefix+"api/access/request", s.authed(s.requestAccess))
	mux.HandleFunc("GET "+Prefix+"api/admin/users", s.authed(s.admin(s.adminUsers)))
	mux.HandleFunc("GET "+Prefix+"api/admin/access", s.authed(s.admin(s.adminAccess)))
	mux.HandleFunc("POST "+Prefix+"api/admin/decide", s.authed(s.admin(s.adminDecide)))
	mux.HandleFunc("GET "+Prefix+"dl/{ticket}", s.download)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The page is one file with its own script and style; the only
		// outside script is Telegram's bridge, which is what makes it a Mini
		// App. Images are data: URIs (the QR codes) and nothing else.
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline' https://telegram.org; "+
			"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; "+
			"frame-ancestors https://web.telegram.org https://*.telegram.org; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// --- middleware ---

type handler func(w http.ResponseWriter, r *http.Request, user User)

// initHeader carries the signed init data on API calls. A header rather than
// the query string, so it does not land in access logs along the way.
const initHeader = "X-Telegram-Init-Data"

func (s *Server) authed(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := Verify(r.Header.Get(initHeader), s.token, s.now())
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrStale) {
				// 419 is not standard, 401 would make the page ask to log in
				// to something that has no login; 403 with the reason reads
				// right: the client must reopen the app.
				status = http.StatusForbidden
			}
			jsonError(w, status, err.Error())
			return
		}
		// Recorded like a message would be: the registry is how an admin sees
		// a name instead of a number.
		s.access.Register(state.User{
			ID: user.ID, Username: user.Username,
			FirstName: user.FirstName, LastName: user.LastName,
		})
		next(w, r, user)
	}
}

func (s *Server) allowed(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request, user User) {
		if !s.access.IsAllowed(user.ID) {
			jsonError(w, http.StatusForbidden, "access not granted")
			return
		}
		next(w, r, user)
	}
}

func (s *Server) admin(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request, user User) {
		if !s.access.IsAdmin(user.ID) {
			jsonError(w, http.StatusForbidden, "admin only")
			return
		}
		next(w, r, user)
	}
}

// --- page ---

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	page, err := static.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "page missing from the build", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

// --- API: who am I ---

type meResponse struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Allowed  bool       `json:"allowed"`
	Pending  bool       `json:"pending"`
	Admin    bool       `json:"admin"`
	Hello    string     `json:"hello"`
	Stats    *statsJSON `json:"stats,omitempty"`
	APK      *apkJSON   `json:"apk,omitempty"`
	HasSub   bool       `json:"has_subscription"`
	Labels   labels     `json:"labels"`
	NodeTags []string   `json:"node_tags,omitempty"`
}

type statsJSON struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Conns    int64 `json:"conns"`
	Active   int64 `json:"active"`
}

type apkJSON struct {
	Version string `json:"version,omitempty"`
	URL     string `json:"url"`
}

// labels are the configured captions the page reuses, so a rebranded
// deployment is rebranded here too.
type labels struct {
	Apps map[string]string `json:"apps"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, user User) {
	out := meResponse{
		ID:      user.ID,
		Name:    strings.TrimSpace(user.FirstName + " " + user.LastName),
		Allowed: s.access.IsAllowed(user.ID),
		Admin:   s.access.IsAdmin(user.ID),
		Pending: slices.Contains(s.access.Pending(), user.ID),
		Hello:   s.cfg.UI.Hello,
		Labels:  labels{Apps: s.cfg.UI.ClientApps},
	}
	if out.Allowed {
		if stat, found, err := s.svc.Stats(r.Context(), uid(user)); err == nil && found {
			out.Stats = &statsJSON{Upload: stat.Upload, Download: stat.Download, Conns: stat.ConnCount, Active: stat.Active}
		}
		if url := s.cfg.Paths.APKURL; url != "" {
			out.APK = &apkJSON{Version: s.cfg.Paths.APKVersion, URL: url}
		}
	}
	writeJSON(w, out)
}

// --- API: methods ---

// Kinds, the same letters the bot's callbacks use.
const (
	kindInbound  = "i"
	kindEndpoint = "e"
	kindWARP     = "w"
	kindWDTT     = "v"
)

type methodJSON struct {
	Kind   string `json:"kind"`
	Tag    string `json:"tag"`
	Label  string `json:"label"`
	Client string `json:"client"`
	Desc   string `json:"desc,omitempty"`
	Apps   string `json:"apps,omitempty"`
}

func (s *Server) methods(w http.ResponseWriter, r *http.Request, user User) {
	inbounds, err := s.svc.UserInbounds(r.Context())
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	endpoints, err := s.svc.OfferedEndpoints(r.Context())
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	var out []methodJSON
	for _, in := range inbounds {
		out = append(out, s.method(kindInbound, in.Tag, in.Type))
	}
	for _, ep := range endpoints {
		out = append(out, s.method(kindEndpoint, ep.Tag, "awg"))
	}
	warp := s.method(kindWARP, "warp", "warp")
	warp.Label = s.button("warp")
	wdtt := s.method(kindWDTT, "wdtt", "wdtt")
	wdtt.Label = s.button("wdtt")
	out = append(out, warp, wdtt)
	writeJSON(w, out)
}

func (s *Server) method(kind, tag, protocol string) methodJSON {
	m := methodJSON{Kind: kind, Tag: tag, Label: s.tagLabel(tag, protocol), Desc: s.cfg.UI.ProtoDesc[tag]}
	m.Client = s.cfg.UI.ClientHint[tag]
	if m.Client == "" {
		m.Client = s.cfg.UI.ClientHint[kind]
	}
	if m.Client == "" {
		m.Client = s.button("default_client")
	}
	m.Apps = s.cfg.UI.ClientApps[tag]
	if m.Apps == "" {
		m.Apps = s.cfg.UI.ClientApps["default"]
	}
	return m
}

func (s *Server) tagLabel(tag, protocol string) string {
	if l := s.cfg.UI.TagLabel[tag]; l != "" {
		return l
	}
	if l := s.cfg.UI.ProtoLabel[protocol]; l != "" {
		return l
	}
	return protocol
}

func (s *Server) button(key string) string {
	if t := s.cfg.UI.Buttons[key]; t != "" {
		return t
	}
	return key
}

// --- API: issue a method ---

type issueRequest struct {
	Kind string `json:"kind"`
	Tag  string `json:"tag"`
}

// issueResponse is one delivered method. Text is what a QR encodes and what a
// copy button copies: the share link, or the whole config for the formats
// that have no link. A file, when the client needs one, is fetched through a
// short-lived ticket, because the page cannot hand bytes to Telegram's
// download prompt directly.
type issueResponse struct {
	Kind     string `json:"kind"` // "link", "conf" or "json"
	Label    string `json:"label"`
	Text     string `json:"text"`
	Filename string `json:"filename,omitempty"`
	Ticket   string `json:"ticket,omitempty"`
	Client   string `json:"client"`
	Apps     string `json:"apps"`
	Desc     string `json:"desc,omitempty"`
	QR       bool   `json:"qr"`
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, user User) {
	var req issueRequest
	if err := readJSON(r, &req); err != nil || req.Tag == "" || strings.ContainsAny(req.Tag, "/:") {
		jsonError(w, http.StatusBadRequest, "kind and tag are required")
		return
	}
	ctx := r.Context()
	name := uid(user)
	var out issueResponse
	var file []byte

	switch req.Kind {
	case kindEndpoint:
		conf, err := s.svc.AWGConf(ctx, req.Tag, name)
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		out = issueResponse{Kind: "conf", Text: conf, Filename: shortProfileName(name) + ".conf"}
		file = []byte(conf)
	case kindWARP:
		config, err := s.svc.WARPChainConfig(ctx, name)
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		out = issueResponse{Kind: "json", Text: string(config), Filename: "warp-" + name + ".json"}
		file = config
	case kindWDTT:
		config, err := s.svc.WDTTConfig(ctx, name)
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		out = issueResponse{Kind: "json", Text: string(config), Filename: "wdtt-" + name + ".json"}
		file = config
	case kindInbound:
		if botcfg.JSONTags()[req.Tag] {
			config, err := s.svc.JSONConfig(ctx, req.Tag, name)
			if err != nil {
				jsonError(w, http.StatusBadGateway, err.Error())
				return
			}
			out = issueResponse{Kind: "json", Text: string(config), Filename: req.Tag + "-" + name + ".json"}
			file = config
			break
		}
		link, err := s.svc.Link(ctx, req.Tag, name)
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		out = issueResponse{Kind: "link", Text: link}
	default:
		jsonError(w, http.StatusBadRequest, "unknown kind")
		return
	}

	protocol := map[string]string{kindEndpoint: "awg", kindWARP: "warp", kindWDTT: "wdtt"}[req.Kind]
	m := s.method(req.Kind, req.Tag, protocol)
	if req.Kind == kindWARP || req.Kind == kindWDTT {
		m.Label = s.button(req.Tag)
	}
	out.Label, out.Client, out.Apps, out.Desc = m.Label, m.Client, m.Apps, m.Desc
	out.QR = qrFits(out.Text)
	if file != nil {
		out.Ticket = s.files.put(user.ID, out.Filename, file)
	}
	writeJSON(w, out)
}

// --- API: subscription ---

type subscriptionResponse struct {
	Nodes  int    `json:"nodes"`
	CF     string `json:"cf,omitempty"`
	Direct string `json:"direct,omitempty"`
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request, user User) {
	name := uid(user)
	bundle, err := s.svc.Bundle(r.Context(), name, true)
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	token, err := s.store.SubscriptionToken(name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Same two steps as the bot's button: the cache is written now so the
	// first poll is not a 404, and the hash is adopted so the refresh loop
	// does not announce a change to the person who just asked for it.
	if err := s.store.SetBundleCache(token, bundle); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hash, err := clientcfg.StructuralHash(bundle); err == nil {
		_ = s.store.UpdateSubscriptions(func(fresh state.Subscriptions) error {
			meta, ok := fresh[token]
			if !ok {
				return nil
			}
			meta.LastHash = hash
			fresh[token] = meta
			return nil
		})
	}
	out := subscriptionResponse{Nodes: countNodes(bundle)}
	if host := s.cfg.Subscription.HostCF; host != "" {
		out.CF = "https://" + host + "/sub/" + token
	}
	if host := s.cfg.Subscription.HostDirect; host != "" {
		out.Direct = "http://" + host + "/sub/" + token
	}
	writeJSON(w, out)
}

// --- API: QR ---

// qrLimit is where a QR of a config stops being scannable in practice; the
// encoder itself gives up a little above this.
const qrLimit = 2800

func qrFits(text string) bool { return text != "" && len(text) <= qrLimit }

func (s *Server) qr(w http.ResponseWriter, r *http.Request, user User) {
	var req struct {
		Text string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil || !qrFits(req.Text) {
		jsonError(w, http.StatusBadRequest, "text is missing or too long for a QR code")
		return
	}
	png, err := qrcode.Encode(req.Text, qrcode.Medium, 512)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

// --- API: access ---

func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request, user User) {
	if s.access.IsAllowed(user.ID) {
		writeJSON(w, map[string]any{"allowed": true})
		return
	}
	s.access.RequestAccess(user.ID)
	if s.OnAccessRequest != nil {
		s.OnAccessRequest(r.Context(), user.ID)
	}
	writeJSON(w, map[string]any{"allowed": false, "pending": true})
}

// --- API: admin ---

type adminUser struct {
	Name     string   `json:"name"`
	Display  string   `json:"display,omitempty"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Active   int64    `json:"active"`
	Inbounds []string `json:"inbounds"`
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request, _ User) {
	accounts, err := s.svc.Accounts(r.Context())
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	rows, err := s.svc.AllStats(r.Context())
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	stats := make(map[string]manage.UserStat, len(rows))
	for _, row := range rows {
		stats[row.User] = row
	}
	out := make([]adminUser, 0, len(accounts))
	for name, inbounds := range accounts {
		st := stats[name]
		row := adminUser{Name: name, Upload: st.Upload, Download: st.Download, Active: st.Active, Inbounds: inbounds}
		if id, err := strconv.ParseInt(name, 10, 64); err == nil {
			row.Display = s.access.DisplayName(id)
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Download != out[j].Download {
			return out[i].Download > out[j].Download
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, out)
}

type accessEntry struct {
	ID      int64  `json:"id"`
	Display string `json:"display"`
}

func (s *Server) adminAccess(w http.ResponseWriter, _ *http.Request, _ User) {
	entries := func(ids []int64) []accessEntry {
		out := make([]accessEntry, 0, len(ids))
		for _, id := range ids {
			out = append(out, accessEntry{ID: id, Display: s.access.DisplayName(id)})
		}
		return out
	}
	writeJSON(w, map[string]any{
		"pending":   entries(s.access.Pending()),
		"whitelist": entries(s.access.Whitelist()),
	})
}

func (s *Server) adminDecide(w http.ResponseWriter, r *http.Request, _ User) {
	var req struct {
		ID     int64  `json:"id"`
		Action string `json:"action"`
	}
	if err := readJSON(r, &req); err != nil || req.ID == 0 {
		jsonError(w, http.StatusBadRequest, "id and action are required")
		return
	}
	var err error
	var notice string
	switch req.Action {
	case "approve":
		err = s.access.Approve(req.ID)
		notice = s.cfg.UI.AccessGranted
	case "reject":
		err = s.access.Reject(req.ID)
		notice = s.cfg.UI.AccessRefused
	case "revoke":
		err = s.access.Revoke(req.ID)
	default:
		jsonError(w, http.StatusBadRequest, "action must be approve, reject or revoke")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if notice != "" && s.Tell != nil {
		s.Tell(r.Context(), req.ID, notice)
	}
	writeJSON(w, map[string]any{"ok": true})
}

// --- file tickets ---

// A ticket is a one-time, short-lived handle to a generated file. The page
// asks Telegram to download a URL, and Telegram fetches it without the page's
// headers, so the URL itself has to be the credential: random, bound to the
// user who generated it, and gone after one use or five minutes.
type ticketStore struct {
	mu   sync.Mutex
	ttl  time.Duration
	open map[string]ticket
}

type ticket struct {
	owner    int64
	filename string
	data     []byte
	expires  time.Time
}

func newTicketStore(ttl time.Duration) *ticketStore {
	return &ticketStore{ttl: ttl, open: map[string]ticket{}}
}

func (t *ticketStore) put(owner int64, filename string, data []byte) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	id := hex.EncodeToString(raw)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, v := range t.open {
		if now.After(v.expires) {
			delete(t.open, k)
		}
	}
	t.open[id] = ticket{owner: owner, filename: filename, data: data, expires: now.Add(t.ttl)}
	return id
}

func (t *ticketStore) take(id string) (ticket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk, ok := t.open[id]
	if !ok {
		return ticket{}, false
	}
	delete(t.open, id)
	if time.Now().After(tk.expires) {
		return ticket{}, false
	}
	return tk, true
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	tk, ok := s.files.take(r.PathValue("ticket"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", tk.filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(tk.data)))
	_, _ = w.Write(tk.data)
}

// --- helpers ---

func uid(user User) string { return strconv.FormatInt(user.ID, 10) }

// shortProfileName matches the bot's: WireGuard clients accept at most 15
// characters of tunnel name, taken from the filename.
func shortProfileName(uid string) string {
	suffix := uid
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	return "amnezia-" + suffix
}

func countNodes(bundle []byte) int {
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return 0
	}
	return len(parsed.Outbounds)
}

func readJSON(r *http.Request, into any) error {
	body := http.MaxBytesReader(nil, r.Body, 64<<10)
	defer body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(body); err != nil {
		return err
	}
	return json.Unmarshal(buf.Bytes(), into)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
