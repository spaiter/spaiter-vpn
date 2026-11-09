package cli

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statsDB(t *testing.T, withInbounds bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "user_stats.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statements := []string{`CREATE TABLE user_stats_daily (user TEXT, date TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`}
	if withInbounds {
		today := time.Now().Format("2006-01-02")
		statements = append(statements,
			`CREATE TABLE user_inbounds_daily (user TEXT, date TEXT, inbound TEXT, upload INTEGER, download INTEGER,
				conn_count INTEGER, bulk_conns INTEGER, max_download INTEGER)`,
			`INSERT INTO user_inbounds_daily VALUES ('alice', '`+today+`', 'vless-reality-in', 0, 1000000, 100, 0, 30000)`,
			`INSERT INTO user_inbounds_daily VALUES ('bob', '`+today+`', 'vless-reality-in', 0, 1000000, 100, 0, 50000)`,
			`INSERT INTO user_inbounds_daily VALUES ('alice', '`+today+`', 'vless-xhttp-in', 0, 104857600, 10, 4, 52428800)`)
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestStatsByInbound(t *testing.T) {
	var out bytes.Buffer
	if err := runStats(context.Background(), &out, []string{"-db", statsDB(t, true), "-inbounds", "-days", "2"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.String(), "\n")
	var reality, xhttp string
	for _, line := range lines {
		switch {
		case strings.Contains(line, "vless-reality-in"):
			reality = line
		case strings.Contains(line, "vless-xhttp-in"):
			xhttp = line
		}
	}
	// Two users, 200 connections, none bulk, largest from bob.
	if !strings.Contains(reality, " 2 ") || !strings.Contains(reality, " 200 ") || !strings.Contains(reality, "48.8 KiB") {
		t.Fatalf("reality line: %q\n%s", reality, out.String())
	}
	if !strings.Contains(xhttp, " 4 ") || !strings.Contains(xhttp, "50.0 MiB") {
		t.Fatalf("xhttp line: %q\n%s", xhttp, out.String())
	}
	// Ordered by download within a day: the bulk transport first.
	if strings.Index(out.String(), "vless-xhttp-in") > strings.Index(out.String(), "vless-reality-in") {
		t.Errorf("not ordered by download:\n%s", out.String())
	}
}

func TestStatsByInboundOnAnOlderCore(t *testing.T) {
	err := runStats(context.Background(), &bytes.Buffer{}, []string{"-db", statsDB(t, false), "-inbounds"})
	if err == nil || !strings.Contains(err.Error(), "does not account traffic per inbound") {
		t.Fatalf("err = %v", err)
	}
}
