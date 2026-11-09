package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// --- listening sockets ---

// Listeners reports which local ports have something bound to them, read from
// /proc/net. It needs no privileges and no network round trip, and it sees
// UDP inbounds (hysteria2, tuic, wireguard) that a TCP connect cannot.
//
// The bot runs with the host's network, so these are the host's sockets.
type Listeners struct {
	// Root is where proc lives; tests point it at a fixture.
	Root string
}

// Ports returns the bound TCP (LISTEN) and UDP ports.
func (l Listeners) Ports() (tcp, udp map[uint16]bool, err error) {
	root := l.Root
	if root == "" {
		root = "/proc"
	}
	tcp, udp = map[uint16]bool{}, map[uint16]bool{}
	read := 0
	for _, f := range []struct {
		name  string
		into  map[uint16]bool
		state string
	}{
		{"tcp", tcp, "0A"}, {"tcp6", tcp, "0A"},
		{"udp", udp, "07"}, {"udp6", udp, "07"},
	} {
		if err := scanProcNet(filepath.Join(root, "net", f.name), f.state, f.into); err != nil {
			if os.IsNotExist(err) {
				continue // a host without IPv6 has no tcp6
			}
			return nil, nil, err
		}
		read++
	}
	if read == 0 {
		return nil, nil, fmt.Errorf("monitor: no /proc/net tables under %s", root)
	}
	return tcp, udp, nil
}

// scanProcNet adds the local ports of the sockets in the given state.
func scanProcNet(path, state string, into map[uint16]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != state {
			continue
		}
		_, port, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil {
			continue
		}
		into[uint16(p)] = true
	}
	return sc.Err()
}

// --- resources ---

// Limits are the usage percentages that count as a problem. Zero disables
// that probe.
type Limits struct {
	MemPct       float64
	DiskPct      float64
	ConntrackPct float64
}

// Resources reads memory, disk and conntrack usage.
type Resources struct {
	Root   string // proc root, "/proc" by default
	Limits Limits
	// Disks are the filesystems to watch, by any path on them.
	Disks []string
}

func (r Resources) root() string {
	if r.Root == "" {
		return "/proc"
	}
	return r.Root
}

// Checks returns one check per watched resource, so an alert says which.
func (r Resources) Checks() []Check {
	var out []Check
	if r.Limits.MemPct > 0 {
		out = append(out, Check{Key: "res:mem", Label: "Память", Group: GroupResources,
			Run: func(context.Context) Result { return r.mem() }})
	}
	if r.Limits.DiskPct > 0 {
		for _, path := range r.Disks {
			out = append(out, Check{Key: "res:disk:" + path, Label: "Диск " + path, Group: GroupResources,
				Run: func(context.Context) Result { return r.disk(path) }})
		}
	}
	if r.Limits.ConntrackPct > 0 {
		out = append(out, Check{Key: "res:conntrack", Label: "conntrack", Group: GroupResources,
			Run: func(context.Context) Result { return r.conntrack() }})
	}
	return out
}

func (r Resources) mem() Result {
	data, err := os.ReadFile(filepath.Join(r.root(), "meminfo"))
	if err != nil {
		return Result{Status: Unknown, Detail: err.Error()}
	}
	info := map[string]uint64{}
	for line := range strings.Lines(string(data)) {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, _ := strconv.ParseUint(fields[0], 10, 64)
		info[name] = v * 1024
	}
	total, avail := info["MemTotal"], info["MemAvailable"]
	if total == 0 {
		return Result{Status: Unknown, Detail: "MemTotal не найден"}
	}
	used := total - min(avail, total)
	return r.verdict(used, total, r.Limits.MemPct, "")
}

func (r Resources) disk(path string) Result {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Result{Status: Unknown, Detail: err.Error()}
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total == 0 {
		return Result{Status: Unknown, Detail: "пустая ФС"}
	}
	return r.verdict(total-min(free, total), total, r.Limits.DiskPct, "")
}

func (r Resources) conntrack() Result {
	read := func(name string) (uint64, error) {
		data, err := os.ReadFile(filepath.Join(r.root(), "sys", "net", "netfilter", name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	count, err := read("nf_conntrack_count")
	if err != nil {
		return Result{Status: Unknown, Detail: "conntrack не загружен"}
	}
	limit, err := read("nf_conntrack_max")
	if err != nil || limit == 0 {
		return Result{Status: Unknown, Detail: "nf_conntrack_max недоступен"}
	}
	return r.verdict(count, limit, r.Limits.ConntrackPct, "count")
}

func (r Resources) verdict(used, total uint64, limit float64, unit string) Result {
	pct := 100 * float64(used) / float64(total)
	var detail string
	if unit == "count" {
		detail = fmt.Sprintf("%d / %d (%.0f%%)", used, total, pct)
	} else {
		detail = fmt.Sprintf("%s / %s (%.0f%%)", HumanBytes(used), HumanBytes(total), pct)
	}
	status := OK
	if pct >= limit {
		status = Fail
	}
	return Result{Status: status, Detail: detail}
}

// HumanBytes renders a size the way the rest of the bot does.
func HumanBytes(v uint64) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(v)/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.0f МБ", float64(v)/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.0f КБ", float64(v)/(1<<10))
	}
	return fmt.Sprintf("%d Б", v)
}

// --- reachability from outside: check-host.net ---

// World asks check-host.net to open a TCP connection to a target from several
// of its nodes. It is the only probe that sees what a client sees: a port
// can listen locally and still be dropped by the provider or by DPI on the
// way in.
type World struct {
	Client   *http.Client
	BaseURL  string // https://check-host.net by default
	MaxNodes int
	// Wait is how long to poll for results.
	Wait time.Duration
	// Poll is the pause between result requests.
	Poll time.Duration
}

// Probe checks host:port. All nodes failing is a failure; some failing is a
// success with the count in the detail, because a single node of theirs
// having a bad day is not our outage.
func (w World) Probe(ctx context.Context, host string, port int) Result {
	base := w.BaseURL
	if base == "" {
		base = "https://check-host.net"
	}
	nodes := w.MaxNodes
	if nodes <= 0 {
		nodes = 3
	}
	wait, poll := w.Wait, w.Poll
	if wait <= 0 {
		wait = 20 * time.Second
	}
	if poll <= 0 {
		poll = 2 * time.Second
	}
	var start struct {
		RequestID string                     `json:"request_id"`
		Nodes     map[string]json.RawMessage `json:"nodes"`
	}
	q := url.Values{"host": {net.JoinHostPort(host, strconv.Itoa(port))}, "max_nodes": {strconv.Itoa(nodes)}}
	if err := w.get(ctx, base+"/check-tcp?"+q.Encode(), &start); err != nil {
		return Result{Status: Unknown, Detail: "check-host: " + err.Error()}
	}
	if start.RequestID == "" {
		return Result{Status: Unknown, Detail: "check-host: нет request_id"}
	}
	expected := len(start.Nodes)
	deadline := time.Now().Add(wait)
	var ok, answered int
	for time.Now().Before(deadline) {
		if err := sleep(ctx, poll); err != nil {
			return Result{Status: Unknown, Detail: err.Error()}
		}
		// Each node maps to null while it is still working, then to a list:
		// [{"time": 0.1, "address": ...}] on success, [{"error": ...}] on failure.
		var res map[string][]map[string]any
		if err := w.get(ctx, base+"/check-result/"+start.RequestID, &res); err != nil {
			continue
		}
		ok, answered = 0, 0
		for _, v := range res {
			if v == nil {
				continue
			}
			answered++
			if len(v) > 0 && v[0] != nil && v[0]["error"] == nil {
				ok++
			}
		}
		if expected == 0 {
			expected = len(res)
		}
		if answered >= expected && expected > 0 {
			break
		}
	}
	if answered == 0 {
		return Result{Status: Unknown, Detail: "check-host не ответил"}
	}
	detail := fmt.Sprintf("%d/%d узлов", ok, answered)
	if ok == 0 {
		return Result{Status: Fail, Detail: detail}
	}
	return Result{Status: OK, Detail: detail}
}

func (w World) get(ctx context.Context, u string, v any) error {
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// --- egress through a local proxy ---

// Egress fetches a "what is my IP" page through a local SOCKS5 proxy and
// compares the answer to the address traffic should leave from. It proves the
// whole chain end to end -- the outbound, the next hop and its exit -- which
// no amount of port checking does.
type Egress struct {
	Socks    string // host:port of a local socks/mixed inbound
	ExpectIP string // empty: any answer is fine, only reachability is checked
	ProbeURL string // https://api.ipify.org by default
	Timeout  time.Duration
}

// Probe runs the check.
func (e Egress) Probe(ctx context.Context) Result {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	probe := e.ProbeURL
	if probe == "" {
		probe = "https://api.ipify.org"
	}
	dialer, err := proxy.SOCKS5("tcp", e.Socks, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return Result{Status: Fail, Detail: err.Error()}
	}
	ctxDialer, _ := dialer.(proxy.ContextDialer)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if ctxDialer != nil {
					return ctxDialer.DialContext(ctx, network, addr)
				}
				return dialer.Dial(network, addr)
			},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
	if err != nil {
		return Result{Status: Fail, Detail: err.Error()}
	}
	began := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{Status: Fail, Detail: shortErr(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	latency := time.Since(began)
	ip := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return Result{Status: Fail, Latency: latency, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if e.ExpectIP != "" && ip != e.ExpectIP {
		return Result{Status: Fail, Latency: latency, Detail: fmt.Sprintf("выход через %s, ждали %s", clipText(ip, 60), e.ExpectIP)}
	}
	return Result{Status: OK, Latency: latency, Detail: "выход " + clipText(ip, 60)}
}

// shortErr keeps the tail of a wrapped network error, which is the useful part.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i > 8 {
		s = s[i+2:]
	}
	return clipText(s, 120)
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
