// Package exporter serves the core's traffic accounting in Prometheus's text
// format.
//
// It is a port of a Python exporter that had been running beside Grafana, and
// the metric names, label keys and output order are reproduced exactly: the
// dashboards built on them are the reason this exists, and renaming anything
// would silently empty a panel rather than break loudly.
//
// Two deliberate departures, both recorded here rather than left to be
// discovered:
//
//   - The ipinfo.io lookup is off unless asked for. See serviceResolver.
//   - Reads open the database read-only. The original did too, but its
//     container mounted the directory read-write for no reason.
//
// Everything is a gauge, including the three names ending in `_total`. That is
// unconventional — a `_total` suffix normally means a counter — but it is what
// the dashboards were built against, so it stays.
package exporter

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Options configures the exporter. The environment variable names and defaults
// match the Python exporter, so an existing compose service keeps working with
// its environment untouched.
type Options struct {
	// DatabasePath is SINGBOX_DB.
	DatabasePath string
	// LogPath is SINGBOX_LOG.
	LogPath string
	// Listen is the address built from PORT.
	Listen string
	// HistoryDays is SINGBOX_HISTORY_DAYS.
	HistoryDays int
	// ServiceTopN is SINGBOX_SERVICE_TOP_N.
	ServiceTopN int
	// ServiceLookupTimeout is SINGBOX_SERVICE_LOOKUP_TIMEOUT.
	ServiceLookupTimeout time.Duration
	// ServiceLookupIPInfo enables the third-party lookup. Default false.
	ServiceLookupIPInfo bool
}

// Defaults mirrors the Python exporter's defaults exactly.
func Defaults() Options {
	return Options{
		DatabasePath:         "/data/user_stats.db",
		LogPath:              "/data/sing-box.log",
		Listen:               ":9102",
		HistoryDays:          31,
		ServiceTopN:          100,
		ServiceLookupTimeout: 600 * time.Millisecond,
	}
}

// Exporter collects and serves the metrics.
type Exporter struct {
	opts     Options
	services *serviceResolver
	xdp      *xdpCounter
}

// New builds an exporter.
func New(opts Options) *Exporter {
	return &Exporter{
		opts:     opts,
		services: newServiceResolver(opts.ServiceLookupIPInfo, opts.ServiceLookupTimeout),
		xdp:      newXDPCounter(opts.LogPath),
	}
}

// Run serves /metrics until the context is cancelled.
func (e *Exporter) Run(stop <-chan struct{}) error {
	// First poll before serving, so the very first scrape is not reported as
	// zero blocks when the log already has some.
	e.xdp.poll()
	go e.xdp.loop(stop)

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, e.Collect())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "try /metrics", http.StatusNotFound)
	})

	server := &http.Server{Addr: e.opts.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-stop
		server.Close()
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// sqliteFamilies are declared before any sample, in this order, because that is
// what the exporter being replaced emitted.
var sqliteFamilies = []struct{ name, help string }{
	{"singbox_user_upload_bytes", "Upload bytes today per user"},
	{"singbox_user_download_bytes", "Download bytes today per user"},
	{"singbox_user_connections", "Connection count today per user"},
	{"singbox_daily_upload_bytes", "Upload bytes per user per day (SQLite history)"},
	{"singbox_daily_download_bytes", "Download bytes per user per day (SQLite history)"},
	{"singbox_daily_connections", "Connection count per user per day (SQLite history)"},
	{"singbox_daily_resource_upload_bytes", "Upload bytes per user per day/resource (SQLite history)"},
	{"singbox_daily_resource_download_bytes", "Download bytes per user per day/resource (SQLite history)"},
	{"singbox_daily_resource_connections", "Connection count per user per day/resource (SQLite history)"},
	{"singbox_monthly_service_upload_bytes", "Upload bytes for top resources over exported history, enriched with service label"},
	{"singbox_monthly_service_download_bytes", "Download bytes for top resources over exported history, enriched with service label"},
	{"singbox_monthly_service_connections", "Connection count for top resources over exported history, enriched with service label"},
	// Appended, never interleaved: the order above is frozen for dashboards.
	{"singbox_inbound_users", "Users with a connection closed today per inbound"},
	{"singbox_inbound_download_bytes", "Download bytes today per inbound, counted when connections close"},
	{"singbox_inbound_connections", "Connections closed today per inbound"},
	{"singbox_inbound_bulk_connections", "Connections closed today per inbound that downloaded at least 1 MiB"},
	{"singbox_inbound_largest_connection_bytes", "Largest single connection download today per inbound"},
}

var xdpFamilies = []struct{ name, help string }{
	{"singbox_xdp_blocks_total", "XDP IP block events since exporter start"},
	{"singbox_xdp_blocks_by_user_total", "XDP IP block events since exporter start, by attributed user"},
	{"singbox_xdp_blocked_ips_current", "Currently blocked IP count"},
}

// Collect renders one scrape.
func (e *Exporter) Collect() string {
	var b strings.Builder
	for _, f := range sqliteFamilies {
		fmt.Fprintf(&b, "# HELP %s %s\n", f.name, f.help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", f.name)
	}
	for _, line := range e.sqliteMetrics() {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, f := range xdpFamilies {
		fmt.Fprintf(&b, "# HELP %s %s\n", f.name, f.help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", f.name)
	}
	e.xdp.ensurePrimed()
	for _, line := range e.xdp.metrics() {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func (e *Exporter) sqliteMetrics() []string {
	today := time.Now().Format("2006-01-02")
	since := time.Now().AddDate(0, 0, -(e.opts.HistoryDays - 1)).Format("2006-01-02")

	// mode=ro so a scrape can never be the thing that corrupts the accounting
	// database the core is writing to.
	db, err := sql.Open("sqlite", "file:"+e.opts.DatabasePath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return []string{"# sqlite error: " + err.Error()}
	}
	defer db.Close()

	var lines []string
	fail := func(err error) []string {
		// The original reported the failure as a comment and served whatever
		// it had, rather than failing the scrape. Kept: a monitoring endpoint
		// that returns nothing teaches people to ignore it.
		return append(lines, "# sqlite error: "+err.Error())
	}

	rows, err := db.Query(`SELECT user, upload, download, conn_count FROM user_stats_daily WHERE date = ?`, today)
	if err != nil {
		return fail(err)
	}
	for rows.Next() {
		var user string
		var up, dl, cc int64
		if err := rows.Scan(&user, &up, &dl, &cc); err != nil {
			rows.Close()
			return fail(err)
		}
		u := escapeLabel(user)
		lines = append(lines,
			fmt.Sprintf(`singbox_user_upload_bytes{user="%s"} %d`, u, up),
			fmt.Sprintf(`singbox_user_download_bytes{user="%s"} %d`, u, dl),
			fmt.Sprintf(`singbox_user_connections{user="%s"} %d`, u, cc),
		)
	}
	rows.Close()

	rows, err = db.Query(`SELECT user, date, upload, download, conn_count FROM user_stats_daily WHERE date >= ? ORDER BY date`, since)
	if err != nil {
		return fail(err)
	}
	for rows.Next() {
		var user, d string
		var up, dl, cc int64
		if err := rows.Scan(&user, &d, &up, &dl, &cc); err != nil {
			rows.Close()
			return fail(err)
		}
		u := escapeLabel(user)
		lines = append(lines,
			fmt.Sprintf(`singbox_daily_upload_bytes{user="%s",date="%s"} %d`, u, d, up),
			fmt.Sprintf(`singbox_daily_download_bytes{user="%s",date="%s"} %d`, u, d, dl),
			fmt.Sprintf(`singbox_daily_connections{user="%s",date="%s"} %d`, u, d, cc),
		)
	}
	rows.Close()

	rows, err = db.Query(`SELECT user, date, resource, upload, download, conn_count FROM user_resources_daily WHERE date >= ? ORDER BY date`, since)
	if err != nil {
		return fail(err)
	}
	for rows.Next() {
		var user, d, resource string
		var up, dl, cc int64
		if err := rows.Scan(&user, &d, &resource, &up, &dl, &cc); err != nil {
			rows.Close()
			return fail(err)
		}
		u, r := escapeLabel(user), escapeLabel(resource)
		lines = append(lines,
			fmt.Sprintf(`singbox_daily_resource_upload_bytes{user="%s",date="%s",resource="%s"} %d`, u, d, r, up),
			fmt.Sprintf(`singbox_daily_resource_download_bytes{user="%s",date="%s",resource="%s"} %d`, u, d, r, dl),
			fmt.Sprintf(`singbox_daily_resource_connections{user="%s",date="%s",resource="%s"} %d`, u, d, r, cc),
		)
	}
	rows.Close()

	rows, err = db.Query(`
		SELECT user, resource, SUM(upload) AS upload, SUM(download) AS download, SUM(conn_count) AS conn_count
		FROM user_resources_daily
		WHERE date >= ?
		GROUP BY user, resource
		ORDER BY download DESC
		LIMIT ?`, since, e.opts.ServiceTopN)
	if err != nil {
		return fail(err)
	}
	for rows.Next() {
		var user, resource string
		var up, dl, cc int64
		if err := rows.Scan(&user, &resource, &up, &dl, &cc); err != nil {
			rows.Close()
			return fail(err)
		}
		u, r := escapeLabel(user), escapeLabel(resource)
		s := escapeLabel(e.services.Label(resource))
		lines = append(lines,
			fmt.Sprintf(`singbox_monthly_service_upload_bytes{user="%s",service="%s",resource="%s"} %d`, u, s, r, up),
			fmt.Sprintf(`singbox_monthly_service_download_bytes{user="%s",service="%s",resource="%s"} %d`, u, s, r, dl),
			fmt.Sprintf(`singbox_monthly_service_connections{user="%s",service="%s",resource="%s"} %d`, u, s, r, cc),
		)
	}
	rows.Close()

	return append(lines, e.inboundMetrics(db, today)...)
}

// inboundMetrics is today per transport, summed over users: whether an
// inbound carries sustained streams (bulk connections, the largest one) or
// only requests. A core without the per-inbound table yields a comment, not a
// failed scrape: the rest of the accounting is still worth serving.
func (e *Exporter) inboundMetrics(db *sql.DB, today string) []string {
	rows, err := db.Query(`SELECT inbound, COUNT(DISTINCT user), SUM(download), SUM(conn_count), SUM(bulk_conns), MAX(max_download)
		FROM user_inbounds_daily WHERE date = ? GROUP BY inbound`, today)
	if err != nil {
		return []string{"# per-inbound accounting unavailable: " + err.Error()}
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var inbound string
		var users, dl, cc, bulk, largest int64
		if err := rows.Scan(&inbound, &users, &dl, &cc, &bulk, &largest); err != nil {
			return append(lines, "# sqlite error: "+err.Error())
		}
		i := escapeLabel(inbound)
		lines = append(lines,
			fmt.Sprintf(`singbox_inbound_users{inbound="%s"} %d`, i, users),
			fmt.Sprintf(`singbox_inbound_download_bytes{inbound="%s"} %d`, i, dl),
			fmt.Sprintf(`singbox_inbound_connections{inbound="%s"} %d`, i, cc),
			fmt.Sprintf(`singbox_inbound_bulk_connections{inbound="%s"} %d`, i, bulk),
			fmt.Sprintf(`singbox_inbound_largest_connection_bytes{inbound="%s"} %d`, i, largest),
		)
	}
	return lines
}

// escapeLabel escapes a Prometheus label value.
//
// Applied everywhere, including the today-query where the original escaped only
// the double quote. The inconsistency never showed because user names are
// digits and words, but a name with a backslash would have produced a line no
// parser accepts.
func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

// sortedUsers keeps the by-user series in a stable order, as the original did.
func sortedUsers(counts map[string]int64) []string {
	users := make([]string, 0, len(counts))
	for u := range counts {
		users = append(users, u)
	}
	sort.Strings(users)
	return users
}
