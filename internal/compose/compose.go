// Package compose runs the generated Compose project through a detected Docker
// CLI. It is shared by the user-facing up command and bootstrap so container
// lifecycle changes always go through the Compose source of truth.
package compose

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
)

// Runner is the narrow container lifecycle surface used by bootstrap. The
// operations are typed so callers cannot turn a privileged executor into an
// arbitrary shell endpoint.
type Runner interface {
	Pull(context.Context, string, io.Writer, io.Writer) error
	Up(context.Context, string, io.Writer, io.Writer) error
	// Recreate replaces every service container even when Compose itself did
	// not change. A bind-mounted config changing is invisible to `compose up`,
	// so restart-based migrations need this stronger, still typed operation.
	Recreate(context.Context, string, io.Writer, io.Writer) error
	// StopService quiesces a runtime writer before bootstrap transactionally
	// migrates its state. It accepts service names, never arbitrary arguments.
	StopService(context.Context, string, string, io.Writer, io.Writer) error
	Down(context.Context, string, io.Writer, io.Writer) error
	// Services reports what the project is actually doing. A running container
	// is not proof of a working deployment, but a container that is not running
	// is proof of a broken one, and that is what the health wait reads.
	Services(context.Context, string) ([]ServiceState, error)
	// Logs returns recent output for a failure report.
	Logs(ctx context.Context, project, service string, lines int) (string, error)
	DisplayName() string
}

// ExecRunner invokes docker directly or through non-interactive sudo.
type ExecRunner struct {
	command []string
	env     []string
}

// Detect finds a Docker CLI whose daemon accepts a version query. Direct
// access is preferred; sudo is only attempted non-interactively.
func Detect(ctx context.Context) (*ExecRunner, error) {
	for _, candidate := range [][]string{{"docker"}, {"sudo", "-n", "docker"}} {
		if _, err := exec.LookPath(candidate[0]); err != nil {
			continue
		}
		probe := exec.CommandContext(ctx, candidate[0], append(candidate[1:], "version", "--format", "{{.Server.Version}}")...)
		if err := probe.Run(); err == nil {
			return &ExecRunner{command: append([]string(nil), candidate...)}, nil
		}
	}
	return nil, fmt.Errorf("no usable docker: not in PATH, or the daemon refused a version query")
}

// DisplayName preserves the concise command name used by CLI progress output.
func (r *ExecRunner) DisplayName() string {
	if len(r.command) == 0 {
		return "docker"
	}
	return r.command[0]
}

// WithEnvironment returns a runner that adds the given variables to the Docker
// CLI's environment.
//
// Compose interpolation needs the bot token, and this is the least bad way to
// hand it over: not argv, where any local user can read it from /proc; not the
// generated .env, which is mode 0644 and deliberately secret-free; not a shell
// string, which the typed Runner exists to prevent. A child process
// environment is readable only by root and by the process itself.
func (r *ExecRunner) WithEnvironment(values map[string]string) *ExecRunner {
	if len(values) == 0 {
		return r
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	next := &ExecRunner{command: append([]string(nil), r.command...), env: append([]string(nil), r.env...)}
	for _, key := range keys {
		next.env = append(next.env, key+"="+values[key])
	}
	return next
}

func (r *ExecRunner) Pull(ctx context.Context, project string, stdout, stderr io.Writer) error {
	return r.run(ctx, project, stdout, stderr, "pull")
}

func (r *ExecRunner) Up(ctx context.Context, project string, stdout, stderr io.Writer) error {
	// --remove-orphans, because this project is generated: a container in it
	// that the current file does not define came from a previous generation of
	// the same file, and leaving it is how disabling the bot leaves the bot
	// running forever. Nothing a human added by hand lives in a bootstrap
	// project, so there is nothing else here to lose.
	return r.run(ctx, project, stdout, stderr, "up", "-d", "--remove-orphans")
}

func (r *ExecRunner) Recreate(ctx context.Context, project string, stdout, stderr io.Writer) error {
	return r.run(ctx, project, stdout, stderr, "up", "-d", "--force-recreate", "--remove-orphans")
}

func (r *ExecRunner) StopService(ctx context.Context, project, service string, stdout, stderr io.Writer) error {
	if service == "" {
		return fmt.Errorf("compose service is empty")
	}
	return r.run(ctx, project, stdout, stderr, "stop", service)
}

func (r *ExecRunner) Down(ctx context.Context, project string, stdout, stderr io.Writer) error {
	return r.run(ctx, project, stdout, stderr, "down")
}

func (r *ExecRunner) run(ctx context.Context, project string, stdout, stderr io.Writer, action ...string) error {
	if len(r.command) == 0 {
		return fmt.Errorf("docker command is empty")
	}
	args := append(append([]string(nil), r.command[1:]...), "compose", "-f", project)
	args = append(args, action...)
	cmd := exec.CommandContext(ctx, r.command[0], args...)
	if len(r.env) > 0 {
		cmd.Env = append(os.Environ(), r.env...)
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
