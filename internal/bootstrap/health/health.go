// Package health decides whether a started deployment is actually usable.
//
// The distinction it exists for: "the container is running" is necessary and
// nowhere near sufficient. A core that started with an empty secret, failed to
// load its configuration or is crash-looping all present as a running container
// for part of their cycle, and the only symptom an operator ever sees is a user
// reporting that nothing works.
package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/compose"
)

// ErrUnhealthy reports that the deployment did not become usable.
var ErrUnhealthy = errors.New("the deployment did not become healthy")

// Options describes one wait.
type Options struct {
	// Project is the generated compose file.
	Project string
	// Services must all be running for the whole settle window.
	Services []string
	// Compose reads service state and, on failure, recent logs.
	Compose compose.Runner

	// Probe is the authenticated localhost management request. Nil means the
	// wait only proves services are running, which is not enough for success;
	// callers that cannot probe must say so rather than pass nil silently.
	Probe func(context.Context) error

	// Deadline bounds the whole wait.
	Deadline time.Duration
	// Settle is how long everything must stay healthy after it first looks
	// healthy. This is what catches a restart loop: a crash-looping service
	// passes a single sample often enough to be useless as a check.
	Settle time.Duration
	// Interval is the sampling period.
	Interval time.Duration
	// LogLines is how much recent output a failure report carries.
	LogLines int
	// Redact scrubs known secret values out of captured logs. A container that
	// fails to start often prints the environment it was given, and the bot's
	// is a Telegram token. Nil means no scrubbing, which is correct only when
	// the deployment has no credentials.
	Redact func(string) string

	// Now and Sleep are injected so the wait is testable without real time.
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error

	Out io.Writer
}

// DefaultOptions returns the production timings.
func DefaultOptions() Options {
	return Options{
		Deadline: 90 * time.Second,
		Settle:   10 * time.Second,
		Interval: 2 * time.Second,
		LogLines: 40,
	}
}

// Report records what the wait observed.
type Report struct {
	Samples  int
	Waited   time.Duration
	Services []compose.ServiceState
}

// Wait blocks until every service has been running and the management endpoint
// has answered continuously for the settle window, or until the deadline.
func Wait(ctx context.Context, options Options) (*Report, error) {
	if options.Out == nil {
		options.Out = io.Discard
	}
	if options.Compose == nil {
		return nil, fmt.Errorf("the health wait needs a compose runner")
	}
	if options.Probe == nil {
		return nil, fmt.Errorf("the health wait needs a management probe: a running container is not proof the core loaded its configuration")
	}
	if len(options.Services) == 0 {
		return nil, fmt.Errorf("the health wait needs the list of expected services")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Sleep == nil {
		options.Sleep = sleep
	}
	defaults := DefaultOptions()
	if options.Deadline <= 0 {
		options.Deadline = defaults.Deadline
	}
	if options.Settle < 0 {
		options.Settle = defaults.Settle
	}
	if options.Interval <= 0 {
		options.Interval = defaults.Interval
	}
	if options.LogLines <= 0 {
		options.LogLines = defaults.LogLines
	}

	start := options.Now()
	report := &Report{}
	var healthySince time.Time
	var lastProblem error

	for {
		now := options.Now()
		if now.Sub(start) > options.Deadline {
			return report, options.fail(ctx, report, now.Sub(start), lastProblem)
		}

		report.Samples++
		states, problem := options.sample(ctx)
		report.Services = states
		if problem != nil {
			// A single bad sample resets the settle window rather than failing
			// outright: a service that is still starting is not a failure, and
			// one that flaps back to unhealthy must not inherit the time it was
			// healthy before.
			if !healthySince.IsZero() {
				fmt.Fprintf(options.Out, "health: lost readiness, restarting the settle window: %v\n", problem)
			}
			healthySince = time.Time{}
			lastProblem = problem
		} else {
			if healthySince.IsZero() {
				healthySince = now
				fmt.Fprintf(options.Out, "health: services running and the management endpoint answered; settling for %s\n", options.Settle)
			}
			if now.Sub(healthySince) >= options.Settle {
				report.Waited = now.Sub(start)
				fmt.Fprintf(options.Out, "health: ok after %s\n", report.Waited.Truncate(time.Millisecond))
				return report, nil
			}
		}

		if err := options.Sleep(ctx, options.Interval); err != nil {
			return report, err
		}
	}
}

func (o Options) sample(ctx context.Context) ([]compose.ServiceState, error) {
	states, err := o.Compose.Services(ctx, o.Project)
	if err != nil {
		return nil, err
	}
	byService := map[string]compose.ServiceState{}
	for _, state := range states {
		byService[state.Service] = state
	}
	var problems []string
	for _, service := range o.Services {
		state, present := byService[service]
		switch {
		case !present:
			problems = append(problems, fmt.Sprintf("%s is not in the project", service))
		case !state.Running():
			detail := state.State
			if state.Health != "" {
				detail += "/" + state.Health
			}
			if strings.EqualFold(state.State, "exited") {
				detail += fmt.Sprintf(" (exit %d)", state.ExitCode)
			}
			problems = append(problems, fmt.Sprintf("%s is %s", service, detail))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return states, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	if err := o.Probe(ctx); err != nil {
		return states, fmt.Errorf("management endpoint: %w", err)
	}
	return states, nil
}

// fail builds the report an operator can act on: what was wrong, and the recent
// output of the services that were not running.
func (o Options) fail(ctx context.Context, report *Report, waited time.Duration, last error) error {
	report.Waited = waited
	detail := "no sample completed"
	if last != nil {
		detail = last.Error()
	}
	message := fmt.Sprintf(" after %s: %s", waited.Truncate(time.Millisecond), detail)

	running := map[string]bool{}
	for _, state := range report.Services {
		running[state.Service] = state.Running()
	}
	for _, service := range o.Services {
		if running[service] {
			continue
		}
		logs, err := o.Compose.Logs(ctx, o.Project, service, o.LogLines)
		if err != nil {
			message += fmt.Sprintf("\n\n%s logs unavailable: %v", service, err)
			continue
		}
		if o.Redact != nil {
			logs = o.Redact(logs)
		}
		if strings.TrimSpace(logs) == "" {
			// An empty log is itself a diagnosis: the process never ran, so the
			// failure is at the container level and not in the application.
			message += fmt.Sprintf("\n\n%s produced no output, so the process never started", service)
			continue
		}
		message += fmt.Sprintf("\n\nrecent %s output:\n%s", service, strings.TrimRight(logs, "\n"))
	}
	// Wrapped, not formatted in: a caller has to be able to tell an unhealthy
	// deployment apart from a transport failure, and %v would make
	// errors.Is(err, ErrUnhealthy) false while the message still said so.
	return fmt.Errorf("%w%s", ErrUnhealthy, message)
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
