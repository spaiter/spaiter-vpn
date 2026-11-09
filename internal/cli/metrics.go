package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/exporter"
)

func runMetrics(ctx context.Context, out io.Writer, args []string) error {
	defaults := exporter.Defaults()

	fs := newFlagSet("metrics", out)
	dir := fs.String("dir", "", "deployment directory; sets -db and -log from it")
	db := fs.String("db", defaults.DatabasePath, "the core's per-user stats database (env SINGBOX_DB)")
	logPath := fs.String("log", defaults.LogPath, "the core's log file, for ban accounting (env SINGBOX_LOG)")
	listen := fs.String("listen", defaults.Listen, "address to serve /metrics on (env PORT sets the port)")
	historyDays := fs.Int("history-days", defaults.HistoryDays, "days of per-day history to export (env SINGBOX_HISTORY_DAYS)")
	topN := fs.Int("service-top-n", defaults.ServiceTopN, "how many resources get a service label (env SINGBOX_SERVICE_TOP_N)")
	timeout := fs.Duration("service-lookup-timeout", defaults.ServiceLookupTimeout, "per-lookup timeout (env SINGBOX_SERVICE_LOOKUP_TIMEOUT, seconds)")
	ipinfo := fs.Bool("service-lookup-ipinfo", false, "resolve unknown addresses via ipinfo.io — see the warning in -h")
	once := fs.Bool("once", false, "print one scrape to stdout and exit, instead of serving")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn metrics [-dir DIR] [-listen :9102]\n\n")
		fmt.Fprintf(out, "Serves the core's traffic accounting in Prometheus text format. Metric\n")
		fmt.Fprintf(out, "names, label keys and output order match the Python exporter this replaces,\n")
		fmt.Fprintf(out, "so existing dashboards keep working — renaming anything would quietly\n")
		fmt.Fprintf(out, "empty a panel rather than fail loudly.\n\n")
		fmt.Fprintf(out, "⚠️ -service-lookup-ipinfo sends addresses to a third party. Those addresses\n")
		fmt.Fprintf(out, "are the destinations YOUR USERS connected to, so turning it on means this\n")
		fmt.Fprintf(out, "server reports where its users went to ipinfo.io. It is off by default,\n")
		fmt.Fprintf(out, "unlike the exporter being replaced, which did it unconditionally. With it\n")
		fmt.Fprintf(out, "off, an unresolved address appears as the service label itself — which is\n")
		fmt.Fprintf(out, "already the original's behaviour whenever a lookup failed.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := exporter.Options{
		DatabasePath:         *db,
		LogPath:              *logPath,
		Listen:               *listen,
		HistoryDays:          *historyDays,
		ServiceTopN:          *topN,
		ServiceLookupTimeout: *timeout,
		ServiceLookupIPInfo:  *ipinfo,
	}
	// The environment is read with the same names the Python exporter used, so
	// an existing compose service can swap the command and change nothing else.
	applyExporterEnv(&opts, fs.Lookup("db").Value.String() == defaults.DatabasePath)
	if *dir != "" {
		opts.DatabasePath = *dir + "/user_stats.db"
		opts.LogPath = *dir + "/sing-box.log"
	}

	if _, err := os.Stat(opts.DatabasePath); err != nil {
		return fmt.Errorf("stats database %s is not readable: %w\n\nThe core writes it beside config.json, and only when config_output_path is set", opts.DatabasePath, err)
	}

	e := exporter.New(opts)
	if *once {
		fmt.Fprint(out, e.Collect())
		return nil
	}

	stop := make(chan struct{})
	signalCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-signalCtx.Done()
		close(stop)
	}()

	fmt.Fprintf(out, "serving /metrics on %s\n", opts.Listen)
	fmt.Fprintf(out, "  stats db: %s\n", opts.DatabasePath)
	fmt.Fprintf(out, "  log:      %s\n", opts.LogPath)
	if opts.ServiceLookupIPInfo {
		warn("ipinfo.io lookups are ON: this server will report its users' destination addresses to a third party")
	}
	return e.Run(stop)
}

// applyExporterEnv reads the Python exporter's environment variables, so a
// compose service can keep its existing environment block.
func applyExporterEnv(opts *exporter.Options, dbIsDefault bool) {
	if v := os.Getenv("SINGBOX_DB"); v != "" && dbIsDefault {
		opts.DatabasePath = v
	}
	if v := os.Getenv("SINGBOX_LOG"); v != "" {
		opts.LogPath = v
	}
	if v := os.Getenv("PORT"); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			opts.Listen = ":" + v
		}
	}
	if v := os.Getenv("SINGBOX_HISTORY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts.HistoryDays = n
		}
	}
	if v := os.Getenv("SINGBOX_SERVICE_TOP_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts.ServiceTopN = n
		}
	}
	// Seconds as a float, which is how the original expressed it.
	if v := os.Getenv("SINGBOX_SERVICE_LOOKUP_TIMEOUT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			opts.ServiceLookupTimeout = time.Duration(f * float64(time.Second))
		}
	}
}
