package cli

import (
	"testing"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
)

// The daily summary is opt-in: report_times alone, including the defaults,
// must not produce a report.
func TestMonitorReportTimesNeedDailyReport(t *testing.T) {
	mc := botcfg.Defaults().Monitor
	if mc.DailyReport {
		t.Fatal("daily_report must be off by default")
	}
	if len(mc.ReportTimes) == 0 {
		t.Fatal("report_times should keep a default for when the report is turned on")
	}
	if got := monitorReportTimes(mc); got != nil {
		t.Fatalf("report times with daily_report off = %v, want none", got)
	}
	mc.DailyReport = true
	if got := monitorReportTimes(mc); len(got) != len(mc.ReportTimes) {
		t.Fatalf("report times with daily_report on = %v, want %v", got, mc.ReportTimes)
	}
}
