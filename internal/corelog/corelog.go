package corelog

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Detection is one parsed `bittorrent sniff detection` log line.
type Detection struct {
	Network         string
	Detector        string
	Inbound         string
	Source          string
	Destination     string
	DestinationPort uint16
	PayloadBytes    int
	Line            string
}

// detectionLine matches the fork's log line from route.logBitTorrentSniff.
//
// Matching this precisely matters more than it looks: the log file contains
// tens of thousands of lines mentioning "bittorrent" which are NOT detections
// — `router: match[0] => sniff(bittorrent,100ms)` is the sniff rule firing on
// every single connection. Counting those would report a pass on a server that
// detects nothing.
var detectionLine = regexp.MustCompile(
	`bittorrent sniff detection: network=([a-z0-9]+), detector=([a-z0-9-]+), inbound=([^,]*), source=([^,]*), destination=([^,]*), payload_bytes=(\d+)`,
)

// rejectLine matches the routing decision that follows a detection. The rule
// index is not pinned: it depends on how many rules precede the reject rule.
var rejectLine = regexp.MustCompile(`protocol=bittorrent => reject\(([a-z,-]+)\)`)

// LogSlice is a window into the log file, delimited by the offset recorded
// before the probes were sent.
type LogSlice struct {
	Text string
}

// Offset returns the current size of the log file, which is where the slice
// taken after the probes begins.
//
// Marking the file by offset rather than by grepping the whole thing is what
// keeps the result about this run: the live file carries months of history,
// including real detections from real clients.
func Offset(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return info.Size(), nil
}

// ReadSince reads the log file from the given offset.
func ReadSince(path string, offset int64) (*LogSlice, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Size() < offset {
		// The file shrank, so it was rotated or truncated mid-run and the
		// offset no longer means anything. Say so instead of reading a window
		// that silently starts in the wrong place.
		return nil, fmt.Errorf("%s shrank from %d to %d bytes during the run: it was rotated, so the result cannot be trusted", path, offset, info.Size())
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s to %d: %w", path, offset, err)
	}

	var builder strings.Builder
	scanner := bufio.NewScanner(file)
	// Detection lines carry a hex dump of the payload, so they are long.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		builder.WriteString(scanner.Text())
		builder.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return &LogSlice{Text: builder.String()}, nil
}

// Detections parses every detection line in the slice.
func (s *LogSlice) Detections() []Detection {
	var out []Detection
	for _, match := range detectionLine.FindAllStringSubmatch(s.Text, -1) {
		payloadBytes, _ := strconv.Atoi(match[6])
		d := Detection{
			Network:      match[1],
			Detector:     match[2],
			Inbound:      match[3],
			Source:       match[4],
			Destination:  match[5],
			PayloadBytes: payloadBytes,
			Line:         match[0],
		}
		d.DestinationPort = portOf(match[5])
		out = append(out, d)
	}
	return out
}

// Rejections returns the reject actions recorded in the slice, as the method
// string the rule printed (for example "drop,xdp-block").
func (s *LogSlice) Rejections() []string {
	var out []string
	for _, match := range rejectLine.FindAllStringSubmatch(s.Text, -1) {
		out = append(out, match[1])
	}
	return out
}

// Contains reports whether the slice mentions the given text.
func (s *LogSlice) Contains(text string) bool {
	return strings.Contains(s.Text, text)
}

// Lines returns the slice's size, for reporting.
func (s *LogSlice) Lines() int {
	if s.Text == "" {
		return 0
	}
	return strings.Count(s.Text, "\n")
}

func portOf(hostPort string) uint16 {
	idx := strings.LastIndex(hostPort, ":")
	if idx < 0 {
		return 0
	}
	port, err := strconv.ParseUint(strings.TrimSpace(hostPort[idx+1:]), 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// Summary is an aggregate over a slice of the log.
//
// The raw lines are nearly unreadable: a detection carries a hex dump of its
// payload, so one event spans dozens of lines. What an operator wants to know
// is which detectors fired, against whom, and whether anything was actually
// rejected — not to page through 230,000 lines by hand.
type Summary struct {
	Lines      int
	Detections int
	// ByDetector counts events per `detector=` value, which is what says
	// whether the sniffer is working across the board or only catching one
	// shape of traffic.
	ByDetector map[string]int
	// ByInbound attributes events to the inbound they arrived on, which for a
	// WireGuard endpoint means the peer's user name is recoverable from the
	// config.
	ByInbound map[string]int
	// BySource counts events per client address — the practical answer to
	// "who is doing this".
	BySource map[string]int
	// Rejections counts the reject actions, keyed by method
	// ("drop,xdp-block"). A detection with no matching rejection means
	// traffic was identified and then allowed through, which is the one
	// outcome worth noticing immediately.
	Rejections map[string]int
	// XDPBlocks are the lines where a client was actually banned, as opposed
	// to merely dropped.
	XDPBlocks int
	// LocalPeerSkips are bans the core refused because the peer was on
	// loopback. Expected during a self-test and nowhere else.
	LocalPeerSkips int
}

// xdpBlockLine is the core's record of an enforced ban, as opposed to a drop.
var xdpBlockLine = regexp.MustCompile(`XDP blocked ([0-9a-fA-F:.]+)`)

// Summarise aggregates a slice.
func (s *LogSlice) Summarise() Summary {
	sum := Summary{
		Lines:      s.Lines(),
		ByDetector: map[string]int{},
		ByInbound:  map[string]int{},
		BySource:   map[string]int{},
		Rejections: map[string]int{},
	}
	for _, d := range s.Detections() {
		sum.Detections++
		sum.ByDetector[d.Detector]++
		sum.ByInbound[d.Inbound]++
		sum.BySource[sourceAddr(d.Source)]++
	}
	for _, method := range s.Rejections() {
		sum.Rejections[method]++
	}
	sum.XDPBlocks = len(xdpBlockLine.FindAllString(s.Text, -1))
	sum.LocalPeerSkips = strings.Count(s.Text, "XDP: skipping local peer endpoint")
	return sum
}

// sourceAddr drops the ephemeral port, which differs per connection and would
// otherwise make every event look like a different client.
func sourceAddr(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i > 0 {
		return hostPort[:i]
	}
	return hostPort
}

// ReadAll reads a whole log file. Used where there is no earlier offset to
// compare against, which is the normal case outside the self-test.
func ReadAll(path string) (*LogSlice, error) {
	return ReadSince(path, 0)
}
