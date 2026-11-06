package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

// lazyCompose finds Docker on first use instead of when the apply is wired.
//
// An apply that installs Docker is wired on a host that has none: detecting it
// up front would refuse the very apply that installs it. The engine installs
// before its first Compose call, so by then there is something to find.
type lazyCompose struct {
	env  map[string]string
	once sync.Once
	run  compose.Runner
	err  error
}

func (l *lazyCompose) resolve(ctx context.Context) (compose.Runner, error) {
	l.once.Do(func() {
		runner, err := compose.Detect(ctx)
		if err != nil {
			l.err = err
			return
		}
		if len(l.env) > 0 {
			runner = runner.WithEnvironment(l.env)
		}
		l.run = runner
	})
	return l.run, l.err
}

func (l *lazyCompose) Pull(ctx context.Context, project string, stdout, stderr io.Writer) error {
	r, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	return r.Pull(ctx, project, stdout, stderr)
}

func (l *lazyCompose) Up(ctx context.Context, project string, stdout, stderr io.Writer) error {
	r, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	return r.Up(ctx, project, stdout, stderr)
}

func (l *lazyCompose) Recreate(ctx context.Context, project string, stdout, stderr io.Writer) error {
	r, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	return r.Recreate(ctx, project, stdout, stderr)
}

func (l *lazyCompose) StopService(ctx context.Context, project, service string, stdout, stderr io.Writer) error {
	r, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	return r.StopService(ctx, project, service, stdout, stderr)
}

func (l *lazyCompose) Down(ctx context.Context, project string, stdout, stderr io.Writer) error {
	r, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	return r.Down(ctx, project, stdout, stderr)
}

func (l *lazyCompose) Services(ctx context.Context, project string) ([]compose.ServiceState, error) {
	r, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return r.Services(ctx, project)
}

func (l *lazyCompose) Logs(ctx context.Context, project, service string, lines int) (string, error) {
	r, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return r.Logs(ctx, project, service, lines)
}

func (l *lazyCompose) DisplayName() string { return "docker" }

// lazyCheck is the configuration validator's counterpart: the image-based
// check needs the daemon the same apply installs.
func lazyCheck(binary, image string, out io.Writer) func(context.Context, []byte) error {
	var once sync.Once
	var checker *singbox.Checker
	var err error
	return func(ctx context.Context, config []byte) error {
		once.Do(func() {
			checker, err = singbox.Detect(ctx, binary, image)
			if errors.Is(err, singbox.ErrUnavailable) {
				err = fmt.Errorf("%w even after installing Docker", err)
			}
			if err == nil {
				fmt.Fprintf(out, "validating generated configuration with %s\n", checker.Describe())
			}
		})
		if err != nil {
			return err
		}
		return checker.Check(ctx, config)
	}
}
