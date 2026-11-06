package cli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/hostinfo"

	_ "modernc.org/sqlite"
)

type userTotal struct {
	user     string
	upload   int64
	download int64
	conns    int64
	days     int
}

func runStats(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("stats", out)
	dir := fs.String("dir", "/etc/sing-box", "deployment directory; the stats database sits beside config.json")
	dbPath := fs.String("db", "", "stats database, if it is not beside the config")
	days := fs.Int("days", 30, "how many days to total over")
	resources := fs.String("user", "", "break one user's traffic down by destination instead")
	top := fs.Int("top", 20, "how many destinations to show with -user")
	inbounds := fs.Bool("inbounds", false, "break traffic down by inbound and day instead: bulk connections and the largest stream per transport")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn stats [-days 30] [-user NAME | -inbounds]\n\n")
		fmt.Fprintf(out, "Per-user traffic, read straight from the core's accounting database.\n")
		fmt.Fprintf(out, "No clash API secret needed, and it works while the core is stopped.\n\n")
		fmt.Fprintf(out, "The database only exists when config_output_path is set — the core gates\n")
		fmt.Fprintf(out, "its per-user accounting on that.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolved := *dbPath
	if resolved == "" {
		resolved = filepath.Join(*dir, "user_stats.db")
	}
	if _, err := os.Stat(resolved); err != nil {
		return fmt.Errorf("no stats database at %s: %w\n\nThe core writes it beside config.json, and only when experimental.clash_api.config_output_path is set", resolved, err)
	}

	// Read-only: a report must never be the thing that corrupts the accounting
	// the core is actively writing.
	db, err := sql.Open("sqlite", "file:"+resolved+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()

	since := time.Now().AddDate(0, 0, -(*days - 1)).Format("2006-01-02")
	if *inbounds {
		return writeInbounds(out, db, since, *days)
	}
	if *resources != "" {
		return writeUserResources(out, db, *resources, since, *days, *top)
	}
	return writeUserTotals(out, db, since, *days)
}

func writeUserTotals(out io.Writer, db *sql.DB, since string, days int) error {
	rows, err := db.Query(`
		SELECT user, SUM(upload), SUM(download), SUM(conn_count), COUNT(DISTINCT date)
		FROM user_stats_daily WHERE date >= ?
		GROUP BY user ORDER BY SUM(download) DESC`, since)
	if err != nil {
		return err
	}
	defer rows.Close()

	var totals []userTotal
	for rows.Next() {
		var t userTotal
		if err := rows.Scan(&t.user, &t.upload, &t.download, &t.conns, &t.days); err != nil {
			return err
		}
		totals = append(totals, t)
	}
	if len(totals) == 0 {
		fmt.Fprintf(out, "No traffic recorded since %s.\n", since)
		return nil
	}

	width := 4
	for _, t := range totals {
		if len(t.user) > width {
			width = len(t.user)
		}
	}
	fmt.Fprintf(out, "last %d days, since %s\n\n", days, since)
	fmt.Fprintf(out, "%-*s %12s %12s %12s %6s\n", width, "user", "upload", "download", "conns", "days")
	var up, down, conns int64
	for _, t := range totals {
		fmt.Fprintf(out, "%-*s %12s %12s %12d %6d\n", width, t.user,
			hostinfo.HumanBytes(uint64(t.upload)), hostinfo.HumanBytes(uint64(t.download)), t.conns, t.days)
		up += t.upload
		down += t.download
		conns += t.conns
	}
	fmt.Fprintf(out, "%-*s %12s %12s %12d\n", width, "total",
		hostinfo.HumanBytes(uint64(up)), hostinfo.HumanBytes(uint64(down)), conns)
	return nil
}

func writeUserResources(out io.Writer, db *sql.DB, user, since string, days, top int) error {
	rows, err := db.Query(`
		SELECT resource, SUM(upload), SUM(download), SUM(conn_count)
		FROM user_resources_daily WHERE user = ? AND date >= ?
		GROUP BY resource ORDER BY SUM(download) DESC LIMIT ?`, user, since, top)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct {
		resource        string
		up, down, conns int64
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.resource, &r.up, &r.down, &r.conns); err != nil {
			return err
		}
		list = append(list, r)
	}
	if len(list) == 0 {
		fmt.Fprintf(out, "No traffic recorded for %q since %s.\n", user, since)
		fmt.Fprintf(out, "\nUser names come from the peer `name` field for WireGuard endpoints and\n")
		fmt.Fprintf(out, "the user list for proxy inbounds; `spaiter-vpn stats` with no -user lists\n")
		fmt.Fprintf(out, "the ones that have traffic.\n")
		return nil
	}

	width := 8
	for _, r := range list {
		if len(r.resource) > width {
			width = len(r.resource)
		}
	}
	fmt.Fprintf(out, "%s — top %d destinations over %d days, since %s\n\n", user, len(list), days, since)
	fmt.Fprintf(out, "%-*s %12s %12s %10s\n", width, "destination", "upload", "download", "conns")
	for _, r := range list {
		fmt.Fprintf(out, "%-*s %12s %12s %10d\n", width, r.resource,
			hostinfo.HumanBytes(uint64(r.up)), hostinfo.HumanBytes(uint64(r.down)), r.conns)
	}
	return nil
}

// writeInbounds shows each transport's days: how much it carried, over how
// many connections, how many of those were sustained streams (at least 1 MiB
// down) and the largest one. A transport whose streams a censor cuts after
// the first request shows many connections, few bulk ones and a small
// maximum, while still moving data.
func writeInbounds(out io.Writer, db *sql.DB, since string, days int) error {
	rows, err := db.Query(`
		SELECT date, inbound, COUNT(DISTINCT user), SUM(download), SUM(conn_count), SUM(bulk_conns), MAX(max_download)
		FROM user_inbounds_daily WHERE date >= ?
		GROUP BY date, inbound ORDER BY date DESC, SUM(download) DESC`, since)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return fmt.Errorf("this core does not account traffic per inbound yet; it needs a core image with user_inbounds_daily")
		}
		return err
	}
	defer rows.Close()
	type row struct {
		date, inbound                   string
		users, down, conns, bulk, large int64
	}
	var all []row
	width := len("inbound")
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.date, &r.inbound, &r.users, &r.down, &r.conns, &r.bulk, &r.large); err != nil {
			return err
		}
		width = max(width, len(r.inbound))
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Fprintf(out, "No per-inbound traffic recorded since %s.\n", since)
		return nil
	}
	fmt.Fprintf(out, "last %d days, since %s; connections are counted on the day they close\n\n", days, since)
	fmt.Fprintf(out, "%-10s %-*s %5s %10s %8s %8s %8s %10s\n", "date", width, "inbound", "users", "download", "conns", "per conn", "bulk", "largest")
	for _, r := range all {
		perConn := uint64(0)
		if r.conns > 0 {
			perConn = uint64(r.down / r.conns)
		}
		fmt.Fprintf(out, "%-10s %-*s %5d %10s %8d %8s %8d %10s\n", r.date, width, r.inbound, r.users,
			hostinfo.HumanBytes(uint64(r.down)), r.conns, hostinfo.HumanBytes(perConn), r.bulk, hostinfo.HumanBytes(uint64(r.large)))
	}
	return nil
}
