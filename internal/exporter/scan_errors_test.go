package exporter

import (
	"strings"
	"testing"
	"time"
)

// A NULL where the core always writes a number is a damaged row. The scrape
// reports it as a comment and keeps serving what it had read so far.
func TestADamagedAccountingRowIsReportedNotFatal(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	cases := map[string][]string{
		"today's totals":       {`INSERT INTO user_stats_daily VALUES ('a', '` + today + `', NULL, 1, 1)`},
		"the daily history":    {`INSERT INTO user_stats_daily VALUES ('a', '` + yesterday + `', NULL, 1, 1)`},
		"the per-resource log": {`INSERT INTO user_resources_daily VALUES ('a', '` + yesterday + `', 'example.net', NULL, 1, 1)`},
		"the per-inbound log":  {`INSERT INTO user_inbounds_daily VALUES ('a', '` + today + `', 'vless-in', 1, 1, NULL, 0, 0)`},
	}
	for name, statements := range cases {
		opts := Defaults()
		opts.DatabasePath = buildDB(t, statements...)
		got := strings.Join(New(opts).sqliteMetrics(), "\n")
		if !strings.Contains(got, "# sqlite error:") {
			t.Errorf("%s: the damage went unreported:\n%s", name, got)
		}
	}
}
