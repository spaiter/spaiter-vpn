package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/corelog"
)

func runLogs(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("logs", out)
	dir := fs.String("dir", "/etc/sing-box", "deployment directory; the log sits beside config.json")
	path := fs.String("file", "", "log file, if it is not beside the config")
	detections := fs.Bool("detections", false, "only the BitTorrent detections, one line each")
	summary := fs.Bool("summary", false, "aggregate instead of listing: detectors, inbounds, sources, rejections")
	grep := fs.String("grep", "", "only lines containing this text")
	level := fs.String("level", "", "only lines at this level (INFO, WARN, ERROR, FATAL, DEBUG)")
	tail := fs.Int("tail", 0, "only the last N matching lines (0 = all)")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn logs [-summary | -detections] [flags]\n\n")
		fmt.Fprintf(out, "Reads the core's log FILE. `docker logs sing-box` is empty by design —\n")
		fmt.Fprintf(out, "log.output points at a file, so anything concluded from the container's\n")
		fmt.Fprintf(out, "stdout about a running instance is worthless. The one exception is a\n")
		fmt.Fprintf(out, "startup failure or a refused reload, which the core prints on stderr\n")
		fmt.Fprintf(out, "before or outside that file.\n\n")
		fmt.Fprintf(out, "-detections exists because grepping for \"bittorrent\" does not work: the\n")
		fmt.Fprintf(out, "sniff RULE logs a line for every connection, so tens of thousands of hits\n")
		fmt.Fprintf(out, "are not detections. Real ones say `detector=`.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolved := *path
	if resolved == "" {
		found, err := findLogFile(*dir)
		if err != nil {
			return err
		}
		resolved = found
	}

	slice, err := corelog.ReadAll(resolved)
	if err != nil {
		return err
	}

	switch {
	case *summary:
		return writeSummary(out, resolved, slice)
	case *detections:
		return writeDetections(out, slice, *tail)
	default:
		return writeLines(out, slice, *grep, *level, *tail)
	}
}

// findLogFile locates the log the way the deployment lays it out: beside
// config.json, because the container mounts that directory at /etc/sing-box
// and log.output names a path inside it.
func findLogFile(dir string) (string, error) {
	candidates := []string{
		filepath.Join(dir, "sing-box.log"),
	}
	// Prefer whatever the config actually says, when it is readable.
	if raw, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
		if named := logOutputFromConfig(raw); named != "" {
			candidates = append([]string{filepath.Join(dir, filepath.Base(named))}, candidates...)
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("no log file found in %s (looked for %s); pass -file", dir, strings.Join(candidates, ", "))
}

func logOutputFromConfig(raw []byte) string {
	var doc struct {
		Log struct {
			Output string `json:"output"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	return doc.Log.Output
}

func writeSummary(out io.Writer, path string, slice *corelog.LogSlice) error {
	s := slice.Summarise()
	fmt.Fprintf(out, "%s\n%d lines\n\n", path, s.Lines)

	if s.Detections == 0 {
		fmt.Fprintf(out, "No BitTorrent detections.\n\n")
		fmt.Fprintf(out, "That is the expected state, not evidence the sniffer is broken — but it\n")
		fmt.Fprintf(out, "is also what a sniffer that never runs looks like. `spaiter-vpn selftest`\n")
		fmt.Fprintf(out, "is what tells the two apart.\n")
		return nil
	}

	fmt.Fprintf(out, "%d detections\n\n", s.Detections)
	writeCounts(out, "by detector", s.ByDetector)
	writeCounts(out, "by inbound", s.ByInbound)
	writeCounts(out, "by source", s.BySource)
	writeCounts(out, "rejections", s.Rejections)

	total := 0
	for _, n := range s.Rejections {
		total += n
	}
	// A detection that was not acted on is a log message, not a defence.
	if total < s.Detections {
		fmt.Fprintf(out, "\n⚠️  %d detections but only %d reject actions: traffic was identified and\n", s.Detections, total)
		fmt.Fprintf(out, "    then allowed through. Check that the reject rule follows the sniff rule\n")
		fmt.Fprintf(out, "    in route.rules — rejecting on `protocol` only works once something has\n")
		fmt.Fprintf(out, "    identified the protocol.\n")
	}
	if s.XDPBlocks > 0 {
		fmt.Fprintf(out, "\n%d clients were banned by the XDP blocker\n", s.XDPBlocks)
	} else if s.LocalPeerSkips > 0 {
		fmt.Fprintf(out, "\nNo bans enforced: %d were skipped as loopback peers, which is what a\n", s.LocalPeerSkips)
		fmt.Fprintf(out, "self-test looks like. A real client arriving from a routable address\n")
		fmt.Fprintf(out, "would have been banned.\n")
	} else if s.Detections > 0 {
		fmt.Fprintf(out, "\nNo bans recorded. Detections were dropped but no client was blocked —\n")
		fmt.Fprintf(out, "either xdp_block is off in the reject rule, or the xdp-blocker service\n")
		fmt.Fprintf(out, "is not attached to the interface carrying the traffic.\n")
	}
	return nil
}

func writeCounts(out io.Writer, title string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	type pair struct {
		key string
		n   int
	}
	pairs := make([]pair, 0, len(counts))
	width := 0
	for k, n := range counts {
		pairs = append(pairs, pair{k, n})
		if len(k) > width {
			width = len(k)
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].n != pairs[j].n {
			return pairs[i].n > pairs[j].n
		}
		return pairs[i].key < pairs[j].key
	})
	fmt.Fprintf(out, "%s:\n", title)
	for _, p := range pairs {
		fmt.Fprintf(out, "  %-*s %d\n", width, p.key, p.n)
	}
	fmt.Fprintln(out)
}

func writeDetections(out io.Writer, slice *corelog.LogSlice, tail int) error {
	events := slice.Detections()
	if tail > 0 && len(events) > tail {
		events = events[len(events)-tail:]
	}
	for _, d := range events {
		// One line per event: the raw record spans a hex dump and an ascii
		// rendering of the payload, which is not what anyone scrolling wants.
		fmt.Fprintf(out, "%-22s %-8s %-18s %-24s -> %s (%d bytes)\n",
			d.Detector, d.Network, d.Inbound, d.Source, d.Destination, d.PayloadBytes)
	}
	fmt.Fprintf(out, "\n%d detections\n", len(slice.Detections()))
	return nil
}

func writeLines(out io.Writer, slice *corelog.LogSlice, grep, level string, tail int) error {
	var matched []string
	scanner := bufio.NewScanner(strings.NewReader(slice.Text))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if grep != "" && !strings.Contains(line, grep) {
			continue
		}
		if level != "" && !strings.Contains(line, strings.ToUpper(level)) {
			continue
		}
		matched = append(matched, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if tail > 0 && len(matched) > tail {
		matched = matched[len(matched)-tail:]
	}
	for _, line := range matched {
		fmt.Fprintln(out, line)
	}
	return nil
}
