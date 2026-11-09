package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the bot ships in a distroless image without a zoneinfo
)

// Notifier delivers a message to every admin.
type Notifier interface {
	NotifyAdmins(ctx context.Context, text string) error
}

// Port is one inbound the core listens on.
type Port struct {
	Tag  string
	Port uint16
}

// InboundSource lists the core's inbounds. It is asked every tick, so an
// inbound added or moved with /port is watched without a restart.
type InboundSource func(ctx context.Context) ([]Port, error)

// Config is how the monitor behaves.
type Config struct {
	Interval  time.Duration
	Threshold int
	Location  *time.Location
	// QuietFrom and QuietTo are local hours; alerts raised in between wait
	// for the end of the quiet period. Equal values disable quiet hours.
	QuietFrom, QuietTo int
	// DigestEvery is the least time between two alert messages. The first
	// alert after a calm period goes out on the next tick; whatever follows
	// is collected into one message.
	DigestEvery time.Duration
	// ReportTimes are local "HH:MM" times for the daily summary.
	ReportTimes []string
	// SkipInbounds are inbound tags not to watch.
	SkipInbounds []string
}

// Monitor runs the checks and alerts the admins.
type Monitor struct {
	cfg       Config
	static    []Check
	inbounds  InboundSource
	listeners Listeners
	notifier  Notifier
	log       *slog.Logger
	statePath string
	now       func() time.Time

	mu      sync.Mutex
	tr      *tracker
	ports   []Port
	lastRun map[string]time.Time
	ticked  time.Time
}

// New builds a monitor. statePath is where counters and the alert queue
// survive a restart; checks are the fixed probes (core, world, egress,
// resources); inbounds may be nil.
func New(cfg Config, statePath string, checks []Check, inbounds InboundSource, notifier Notifier, log *slog.Logger) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.DigestEvery <= 0 {
		cfg.DigestEvery = time.Hour
	}
	m := &Monitor{
		cfg: cfg, static: checks, inbounds: inbounds, notifier: notifier, log: log,
		statePath: statePath, now: time.Now,
		tr: newTracker(cfg.Threshold), lastRun: map[string]time.Time{},
	}
	m.load()
	return m
}

// Run checks every interval until the context ends.
func (m *Monitor) Run(ctx context.Context) error {
	m.primeReport()
	for {
		m.Tick(ctx)
		if err := sleep(ctx, m.cfg.Interval); err != nil {
			return err
		}
	}
}

// Tick is one round: run what is due, update the state, send what is ready.
func (m *Monitor) Tick(ctx context.Context) {
	checks := m.due(ctx)
	results := make([]Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			results[i] = c.Run(cctx)
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	now := m.now()
	m.mu.Lock()
	for i, c := range checks {
		if ev, ok := m.tr.observe(now, c, results[i]); ok {
			m.log.Info("monitor: state change", "check", c.Key, "down", ev.Down, "detail", ev.Detail)
		}
		m.lastRun[c.Key] = now
	}
	m.ticked = now
	m.mu.Unlock()

	m.flush(ctx)
	m.report(ctx)
	m.save()
}

// due assembles this round's checks: the fixed ones that are due, and one
// per inbound against a single read of the socket tables.
func (m *Monitor) due(ctx context.Context) []Check {
	now := m.now()
	all := slices.Clone(m.static)
	inbound, known := m.inboundChecks(ctx)
	all = append(all, inbound...)

	keep := make(map[string]bool, len(all))
	var out []Check
	m.mu.Lock()
	if !known {
		// Without a list from the core nothing can be said to have been
		// removed; keep every inbound it ever reported.
		for key := range m.tr.st.Checks {
			if strings.HasPrefix(key, "in:") {
				keep[key] = true
			}
		}
	}
	for _, c := range all {
		keep[c.Key] = true
		if c.Every > 0 && now.Sub(m.lastRun[c.Key]) < c.Every {
			continue
		}
		out = append(out, c)
	}
	m.tr.forget(now, keep)
	m.mu.Unlock()
	return out
}

// inboundChecks also says whether the list is current, so a core that is
// down does not make its inbounds look removed.
func (m *Monitor) inboundChecks(ctx context.Context) ([]Check, bool) {
	if m.inbounds == nil {
		return nil, true
	}
	ports, err := m.inbounds(ctx)
	m.mu.Lock()
	if err != nil {
		// The core's API being down is its own check; the inbounds keep
		// being watched against the last list it gave.
		ports = m.ports
	} else {
		m.ports = ports
	}
	m.mu.Unlock()

	tcp, udp, lerr := m.listeners.Ports()
	var out []Check
	for _, p := range ports {
		if p.Port == 0 || slices.Contains(m.cfg.SkipInbounds, p.Tag) {
			continue
		}
		out = append(out, Check{
			Key: "in:" + p.Tag, Label: fmt.Sprintf("%s :%d", p.Tag, p.Port), Group: GroupInbounds,
			Run: func(context.Context) Result {
				switch {
				case lerr != nil:
					return Result{Status: Unknown, Detail: lerr.Error()}
				case tcp[p.Port] || udp[p.Port]:
					return Result{Status: OK}
				}
				return Result{Status: Fail, Detail: "порт не слушается"}
			},
		})
	}
	return out, err == nil
}

// --- alerts ---

func (m *Monitor) quiet(t time.Time) bool {
	from, to, h := m.cfg.QuietFrom, m.cfg.QuietTo, t.Hour()
	switch {
	case from == to:
		return false
	case from < to:
		return h >= from && h < to
	}
	return h >= from || h < to
}

// flush sends the queued alerts if it is time to.
func (m *Monitor) flush(ctx context.Context) {
	m.mu.Lock()
	queue := slices.Clone(m.tr.st.Queue)
	last := m.tr.st.LastDigest
	m.mu.Unlock()
	now := m.now()
	if len(queue) == 0 || m.quiet(now.In(m.cfg.Location)) {
		return
	}
	if !last.IsZero() && now.Sub(last) < m.cfg.DigestEvery {
		return
	}
	if err := m.notifier.NotifyAdmins(ctx, m.renderDigest(queue)); err != nil {
		m.log.Warn("monitor: could not send the alert digest", "error", err)
		return
	}
	m.mu.Lock()
	m.tr.st.Queue = m.tr.st.Queue[len(queue):]
	m.tr.st.LastDigest = now
	m.mu.Unlock()
}

// primeReport marks the reports already due today as sent, so a restart in
// the evening does not produce the morning's report.
func (m *Monitor) primeReport() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tr.st.LastReport == "" {
		m.tr.st.LastReport = m.dueReport(m.now())
	}
}

// dueReport is the marker of the latest report time that has passed today,
// or "" if none has.
func (m *Monitor) dueReport(now time.Time) string {
	local := now.In(m.cfg.Location)
	hhmm, day := local.Format("15:04"), local.Format("2006-01-02")
	due := ""
	for _, rt := range m.cfg.ReportTimes {
		if hhmm >= rt {
			if marker := day + " " + rt; marker > due {
				due = marker
			}
		}
	}
	return due
}

func (m *Monitor) report(ctx context.Context) {
	now := m.now()
	m.mu.Lock()
	due := m.dueReport(now)
	if due == "" || m.tr.st.LastReport >= due {
		m.mu.Unlock()
		return
	}
	m.tr.pruneIncidents(now.Add(-48 * time.Hour))
	text := m.renderReport(now)
	m.mu.Unlock()
	if err := m.notifier.NotifyAdmins(ctx, text); err != nil {
		m.log.Warn("monitor: could not send the daily report", "error", err)
		return
	}
	m.mu.Lock()
	m.tr.st.LastReport = due
	m.mu.Unlock()
}

// --- persistence ---

func (m *Monitor) load() {
	if m.statePath == "" {
		return
	}
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.log.Warn("monitor: could not read the state", "error", err)
		}
		return
	}
	var st trackerState
	if err := json.Unmarshal(data, &st); err != nil {
		m.log.Warn("monitor: state is unreadable, starting afresh", "error", err)
		return
	}
	if st.Checks == nil {
		st.Checks = map[string]*checkState{}
	}
	m.tr.st = st
}

func (m *Monitor) save() {
	if m.statePath == "" {
		return
	}
	m.mu.Lock()
	data, err := json.MarshalIndent(m.tr.st, "", " ")
	m.mu.Unlock()
	if err != nil {
		m.log.Warn("monitor: could not encode the state", "error", err)
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.statePath), ".monitor-*")
	if err == nil {
		_, err = tmp.Write(data)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), m.statePath)
		}
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}
	if err != nil {
		m.log.Warn("monitor: could not save the state", "error", err)
	}
}
