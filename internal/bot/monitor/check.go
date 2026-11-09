// Package monitor watches the server from inside the bot and tells the admins
// when something stops working.
//
// It is deliberately small: the checks are the ones a single host can run on
// itself without privileges (listening sockets, the core's API, /proc, a
// public reachability service, an egress probe through a local proxy), the
// alerting is debounced by a failure threshold, and alerts are batched into a
// digest that respects quiet hours. Grafana remains the place for history;
// this is the part that wakes someone up.
package monitor

import (
	"context"
	"time"
)

// Status is the outcome of one probe.
type Status int

const (
	// Unknown means the probe could not reach a verdict -- the reachability
	// service timed out, the core's API is restarting. It neither counts as a
	// failure nor resets one, so a flaky probe cannot raise or clear an alert.
	Unknown Status = iota
	OK
	Fail
)

// Result is what a probe reports.
type Result struct {
	Status  Status
	Latency time.Duration
	// Detail is shown beside the check: "1.2 ГБ / 11 ГБ (78%)", "2/3 узла".
	Detail string
}

// Check is one named probe.
type Check struct {
	// Key identifies the check across restarts; it is what the tracker
	// persists, so renaming a label does not reset the counters.
	Key   string
	Label string
	// Group orders and titles the checks in the status page.
	Group string
	Run   func(ctx context.Context) Result
	// Every slows a check down below the monitor's interval: an external
	// service should not be asked twice a minute. Zero runs it every tick.
	Every time.Duration
	// Threshold overrides the monitor's failure threshold. A slow check
	// needs fewer strikes to raise an alert in reasonable time.
	Threshold int
}

// Groups, in the order the status page shows them.
const (
	GroupCore      = "core"
	GroupInbounds  = "inbounds"
	GroupWorld     = "world"
	GroupEgress    = "egress"
	GroupResources = "resources"
)

var groupOrder = []string{GroupCore, GroupInbounds, GroupWorld, GroupEgress, GroupResources}
