package monitor

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Messages go out with the bot's legacy Markdown, so anything taken from the
// config or from an error (inbound tags are full of underscores) is escaped.
var mdEscaper = strings.NewReplacer("_", `\_`, "*", `\*`, "`", "\\`", "[", `\[`)

func md(s string) string { return mdEscaper.Replace(s) }

var groupTitle = map[string]string{
	GroupCore:      "⚙️ Ядро",
	GroupInbounds:  "📡 Входы",
	GroupWorld:     "🌍 Доступность снаружи (check-host.net)",
	GroupEgress:    "🔗 Выход в интернет",
	GroupResources: "💻 Ресурсы",
}

// renderDigest groups the queued events by check, in the order they first
// happened.
func (m *Monitor) renderDigest(queue []Event) string {
	loc := m.cfg.Location
	var order []string
	byKey := map[string][]Event{}
	for _, e := range queue {
		if _, seen := byKey[e.Key]; !seen {
			order = append(order, e.Key)
		}
		byKey[e.Key] = append(byKey[e.Key], e)
	}
	var b strings.Builder
	b.WriteString("🩺 *Мониторинг*\n")
	for _, key := range order {
		evs := byKey[key]
		first, last := evs[0], evs[len(evs)-1]
		mark := "🟢"
		if last.Down {
			mark = "🔴"
		}
		if len(evs) == 1 {
			word := "восстановлено"
			if last.Down {
				word = "не работает"
			}
			fmt.Fprintf(&b, "%s %s %s — %s%s\n", mark, last.Time.In(loc).Format("15:04"), md(last.Label), word, detail(last.Detail))
			continue
		}
		now := "сейчас в норме"
		if last.Down {
			now = "сейчас не работает"
		}
		fmt.Fprintf(&b, "%s %s: %d событий %s–%s, %s%s\n", mark, md(last.Label), len(evs),
			first.Time.In(loc).Format("15:04"), last.Time.In(loc).Format("15:04"), now, detail(last.Detail))
	}
	return strings.TrimRight(b.String(), "\n")
}

func detail(s string) string {
	if s == "" {
		return ""
	}
	return " (" + md(s) + ")"
}

// renderReport is the daily summary. Called with the lock held.
func (m *Monitor) renderReport(now time.Time) string {
	loc := m.cfg.Location
	since := now.Add(-24 * time.Hour)
	var downs []Event
	for _, e := range m.tr.st.Incidents {
		if e.Down && !e.Time.Before(since) {
			downs = append(downs, e)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "🗓 *Сводка за сутки* — %s\n", now.In(loc).Format("02.01 15:04"))
	if len(downs) == 0 {
		b.WriteString("Сбоев не было ✅\n")
	} else {
		fmt.Fprintf(&b, "Сбоев: %d\n", len(downs))
		for _, e := range downs[max(0, len(downs)-10):] {
			fmt.Fprintf(&b, "  🔴 %s %s%s\n", e.Time.In(loc).Format("15:04"), md(e.Label), detail(e.Detail))
		}
	}
	if down := m.tr.down(); len(down) > 0 {
		b.WriteString("\nСейчас не работает:\n")
		for _, e := range down {
			fmt.Fprintf(&b, "  🔴 %s с %s%s\n", md(e.Label), e.Time.In(loc).Format("02.01 15:04"), detail(e.Detail))
		}
	}
	if res := m.groupLines(GroupResources); len(res) > 0 {
		b.WriteString("\n" + groupTitle[GroupResources] + "\n")
		b.WriteString(strings.Join(res, "\n"))
	}
	return strings.TrimRight(b.String(), "\n")
}

// Status is the page the /health command shows.
func (m *Monitor) Status() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	b.WriteString("🩺 *Состояние сервера*")
	if !m.ticked.IsZero() {
		fmt.Fprintf(&b, " — проверено в %s", m.ticked.In(m.cfg.Location).Format("15:04:05"))
	} else {
		b.WriteString("\nПроверки ещё не прошли, повтори через минуту.")
	}
	b.WriteString("\n")
	for _, g := range groupOrder {
		lines := m.groupLines(g)
		if len(lines) == 0 {
			continue
		}
		b.WriteString("\n" + groupTitle[g] + "\n")
		b.WriteString(strings.Join(lines, "\n") + "\n")
	}
	if n := len(m.tr.st.Queue); n > 0 {
		fmt.Fprintf(&b, "\n⏳ В очереди дайджеста: %d", n)
	}
	return strings.TrimRight(b.String(), "\n")
}

// groupLines renders one group's checks. Called with the lock held.
func (m *Monitor) groupLines(group string) []string {
	type row struct{ label, line string }
	var rows []row
	for _, s := range m.tr.st.Checks {
		if s.group != group || s.checked.IsZero() {
			continue
		}
		mark := "🟢"
		switch {
		case s.Down:
			mark = "🔴"
		case s.last.Status == Fail:
			mark = "🟡"
		case s.last.Status == Unknown:
			mark = "❔"
		}
		line := "  " + mark + " " + md(s.label)
		if s.last.Detail != "" {
			line += " — " + md(s.last.Detail)
		}
		if s.last.Latency > 0 {
			line += fmt.Sprintf(", %d мс", s.last.Latency.Milliseconds())
		}
		rows = append(rows, row{s.label, line})
	}
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.label, b.label) })
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.line
	}
	return out
}
