package exporter

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var (
	// The core logs `XDP blocked <ip> user=<name> for <dur> (total: N)`.
	xdpBlocked = regexp.MustCompile(`XDP blocked .+?\(total: (\d+)\)`)
	// The user field was added to that line later, so it stays optional:
	// older lines, and anything read out of a rotated file, simply have no
	// match and are attributed to "-".
	xdpBlockedUser = regexp.MustCompile(`XDP blocked \S+ user=(\S+) `)
	xdpUnblocked   = regexp.MustCompile(`XDP unblocked .+?\(total: (\d+)\)`)
	ansiEscape     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
)

// xdpCounter accumulates ban events by tailing the core's log.
//
// Counting rather than reading a current value, because the core reports a ban
// only as it happens. The totals are therefore since this process started,
// which is what the metric's help text says and what the exporter being
// replaced did.
type xdpCounter struct {
	path string

	mu        sync.Mutex
	blocks    int64
	byUser    map[string]int64
	current   int64
	offset    int64
	inode     uint64
	haveInode bool
	primed    bool
}

// ensurePrimed does the first read on demand.
//
// Without it a collection that happens before the polling goroutine has run —
// which is exactly what `-once` does — reports zero bans while the log already
// holds some. Found by diffing this exporter's output against the one it
// replaces, not by reading either.
func (c *xdpCounter) ensurePrimed() {
	c.mu.Lock()
	already := c.primed
	c.mu.Unlock()
	if already {
		return
	}
	c.poll()
}

func newXDPCounter(path string) *xdpCounter {
	return &xdpCounter{path: path, byUser: map[string]int64{}}
}

// loop polls until stopped. Ten seconds, as before: a ban is not an event
// anyone watches in real time, and re-reading a 24 MB file more often would
// cost more than it tells.
func (c *xdpCounter) loop(stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			c.poll()
		}
	}
}

func (c *xdpCounter) poll() {
	lines, err := c.readNew()
	if err != nil {
		c.mu.Lock()
		c.primed = true
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.primed = true
	for _, line := range lines {
		if m := xdpBlocked.FindStringSubmatch(line); m != nil {
			c.blocks++
			if total, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				c.current = total
			}
			user := "-"
			if mu := xdpBlockedUser.FindStringSubmatch(line); mu != nil {
				user = mu[1]
			}
			c.byUser[user]++
			continue
		}
		if m := xdpUnblocked.FindStringSubmatch(line); m != nil {
			if total, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				c.current = total
			}
		}
	}
}

// readNew returns the lines appended since the last call, restarting when the
// file has been rotated.
//
// Rotation is detected two ways because the deployment uses copytruncate: the
// inode stays the same and the size drops, so watching the inode alone would
// miss it and the reader would sit past the end of a freshly truncated file,
// never seeing another line. Watching size alone would miss a rename-based
// rotation. Both are checked.
func (c *xdpCounter) readNew() ([]string, error) {
	info, err := os.Stat(c.path)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	var inode uint64
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		inode = stat.Ino
	}
	if (c.haveInode && inode != c.inode) || info.Size() < c.offset {
		c.offset = 0
	}
	c.inode, c.haveInode = inode, true
	offset := c.offset
	c.mu.Unlock()

	file, err := os.Open(c.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Seek(offset, 0); err != nil {
		return nil, err
	}

	// Belt and braces. The rotation check above already resets the offset when
	// the file shrinks, but a negative length here is a panic rather than an
	// error — and a panic in a metrics endpoint takes the exporter down. Found
	// by sabotaging the rotation check and watching this panic instead of
	// failing.
	available := info.Size() - offset
	if available <= 0 {
		return nil, nil
	}
	data := make([]byte, available)
	n, err := file.Read(data)
	if n <= 0 {
		if err != nil {
			return nil, err
		}
		return nil, nil
	}

	c.mu.Lock()
	c.offset = offset + int64(n)
	c.mu.Unlock()

	var lines []string
	for _, line := range splitLines(string(data[:n])) {
		lines = append(lines, ansiEscape.ReplaceAllString(line, ""))
	}
	return lines, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func (c *xdpCounter) metrics() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	lines := []string{fmt.Sprintf("singbox_xdp_blocks_total %d", c.blocks)}
	for _, user := range sortedUsers(c.byUser) {
		lines = append(lines, fmt.Sprintf(`singbox_xdp_blocks_by_user_total{user="%s"} %d`, escapeLabel(user), c.byUser[user]))
	}
	return append(lines, fmt.Sprintf("singbox_xdp_blocked_ips_current %d", c.current))
}
