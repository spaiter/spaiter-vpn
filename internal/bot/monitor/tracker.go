package monitor

import (
	"slices"
	"time"
)

// Event is a check changing state.
type Event struct {
	Time   time.Time `json:"t"`
	Key    string    `json:"key"`
	Label  string    `json:"label"`
	Down   bool      `json:"down"`
	Detail string    `json:"detail,omitempty"`
}

// checkState is what the tracker remembers about one check.
type checkState struct {
	Fails int       `json:"fails"`
	Down  bool      `json:"down"`
	Since time.Time `json:"since,omitzero"`
	// The last verdict, for the status page. Not persisted: after a restart
	// the page should show what is true now, not what was true before.
	last    Result
	label   string
	group   string
	checked time.Time
}

// trackerState is the persisted part.
type trackerState struct {
	Checks     map[string]*checkState `json:"checks"`
	Queue      []Event                `json:"queue,omitempty"`
	Incidents  []Event                `json:"incidents,omitempty"`
	LastDigest time.Time              `json:"last_digest,omitzero"`
	LastReport string                 `json:"last_report,omitempty"`
}

// maxIncidents bounds the history kept for the daily report.
const maxIncidents = 500

// tracker turns a stream of results into state changes.
//
// A check goes down after threshold consecutive failures and comes back up on
// the first success. Unknown results are ignored entirely.
type tracker struct {
	threshold int
	st        trackerState
}

func newTracker(threshold int) *tracker {
	if threshold < 1 {
		threshold = 1
	}
	return &tracker{threshold: threshold, st: trackerState{Checks: map[string]*checkState{}}}
}

// observe records one result and returns the event it caused, if any.
func (t *tracker) observe(now time.Time, c Check, r Result) (Event, bool) {
	s := t.st.Checks[c.Key]
	if s == nil {
		s = &checkState{}
		t.st.Checks[c.Key] = s
	}
	s.label, s.group = c.Label, c.Group
	if r.Status != Unknown || s.checked.IsZero() {
		s.last = r
		s.checked = now
	}
	switch r.Status {
	case OK:
		s.Fails = 0
		if s.Down {
			s.Down = false
			s.Since = now
			return t.record(Event{Time: now, Key: c.Key, Label: c.Label, Detail: r.Detail}), true
		}
	case Fail:
		s.Fails++
		threshold := t.threshold
		if c.Threshold > 0 {
			threshold = c.Threshold
		}
		if !s.Down && s.Fails >= threshold {
			s.Down = true
			s.Since = now
			return t.record(Event{Time: now, Key: c.Key, Label: c.Label, Down: true, Detail: r.Detail}), true
		}
	}
	return Event{}, false
}

func (t *tracker) record(e Event) Event {
	t.st.Queue = append(t.st.Queue, e)
	t.st.Incidents = append(t.st.Incidents, e)
	if n := len(t.st.Incidents); n > maxIncidents {
		t.st.Incidents = slices.Clone(t.st.Incidents[n-maxIncidents:])
	}
	return e
}

// forget drops checks that no longer exist -- an inbound removed from the
// core must not stay "down" in the status page forever. A check that is down
// when it disappears is reported as gone rather than silently dropped.
func (t *tracker) forget(now time.Time, keep map[string]bool) {
	for key, s := range t.st.Checks {
		if keep[key] {
			continue
		}
		if s.Down && s.label != "" {
			t.record(Event{Time: now, Key: key, Label: s.label, Detail: "проверка убрана"})
		}
		delete(t.st.Checks, key)
	}
}

// down lists the checks that are down now, oldest first.
func (t *tracker) down() []Event {
	var out []Event
	for key, s := range t.st.Checks {
		if s.Down {
			out = append(out, Event{Time: s.Since, Key: key, Label: s.label, Down: true, Detail: s.last.Detail})
		}
	}
	slices.SortFunc(out, func(a, b Event) int { return a.Time.Compare(b.Time) })
	return out
}

// pruneIncidents keeps only what the report window can still show.
func (t *tracker) pruneIncidents(before time.Time) {
	t.st.Incidents = slices.DeleteFunc(t.st.Incidents, func(e Event) bool { return e.Time.Before(before) })
}
