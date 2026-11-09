package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ServiceState is one service's state as Compose reports it.
//
// Only the fields the health wait needs. Compose's `ps --format json` carries
// more, and decoding the rest would couple us to a shape that changes between
// Compose releases for no benefit.
type ServiceState struct {
	Service  string `json:"Service"`
	Name     string `json:"Name"`
	State    string `json:"State"`
	Health   string `json:"Health"`
	ExitCode int    `json:"ExitCode"`
}

// Running reports whether the service is up and not failing its healthcheck.
//
// "restarting" is deliberately NOT running. A crash-looping container spends
// part of its cycle in "running", so treating anything but "exited" as healthy
// is how a restart loop gets reported as a successful start — which is exactly
// what happened to the live tunnel stack when it came up with an empty secret.
func (s ServiceState) Running() bool {
	return strings.EqualFold(s.State, "running") && !strings.EqualFold(s.Health, "unhealthy")
}

// Services lists the state of every service in the project.
func (r *ExecRunner) Services(ctx context.Context, project string) ([]ServiceState, error) {
	var stdout, stderr bytes.Buffer
	if err := r.run(ctx, project, &stdout, &stderr, "ps", "--all", "--format", "json"); err != nil {
		return nil, fmt.Errorf("list compose services: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseServices(stdout.Bytes())
}

// parseServices accepts both shapes Compose has emitted for `ps --format json`:
// a JSON array, and one object per line. Which one you get depends on the
// Compose version, so handling a single shape would make the health wait fail
// on hosts that are otherwise fine.
func parseServices(data []byte) ([]ServiceState, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var states []ServiceState
		if err := json.Unmarshal(trimmed, &states); err != nil {
			return nil, fmt.Errorf("decode compose service list: %w", err)
		}
		return states, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var states []ServiceState
	for {
		var state ServiceState
		if err := decoder.Decode(&state); err == io.EOF {
			return states, nil
		} else if err != nil {
			return nil, fmt.Errorf("decode compose service: %w", err)
		}
		states = append(states, state)
	}
}

// Logs returns the recent output of one service, for a failure report.
func (r *ExecRunner) Logs(ctx context.Context, project, service string, lines int) (string, error) {
	var stdout, stderr bytes.Buffer
	if err := r.run(ctx, project, &stdout, &stderr, "logs", "--no-color", "--tail", fmt.Sprint(lines), service); err != nil {
		return "", fmt.Errorf("read %s logs: %w: %s", service, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String() + stderr.String(), nil
}
