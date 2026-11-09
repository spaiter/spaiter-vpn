package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

func runCheck(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("check", out)
	configPath := fs.String("config", "", "a single config file to validate")
	dir := fs.String("dir", "/etc/sing-box", "validate a config directory the way the service loads it (every top-level *.json, merged)")
	image := fs.String("image", singbox.DefaultImage, "sing-box container image")
	binary := fs.String("sing-box", "", "path to a local sing-box binary to validate with instead of the image")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn check [-dir DIR | -config FILE]\n\n")
		fmt.Fprintf(out, "By default validates the whole directory, because that is what the service\n")
		fmt.Fprintf(out, "reads: it runs with `-C <dir>` and merges every top-level *.json it finds.\n")
		fmt.Fprintf(out, "A single-file check passes on a directory that cannot start — an unrelated\n")
		fmt.Fprintf(out, "JSON file beside the config is parsed as configuration, not ignored.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	checker, err := singbox.Detect(ctx, *binary, *image)
	if err != nil {
		return err
	}

	// -config narrows the question to one file deliberately; -dir answers the
	// one that matters for whether the service will start.
	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", *configPath, err)
		}
		fmt.Fprintf(out, "validating the single file %s with %s ...\n", *configPath, checker.Describe())
		if err := checker.Check(ctx, data); err != nil {
			return err
		}
		fmt.Fprintln(out, "ok (this says nothing about the other files in that directory)")
		return nil
	}

	fmt.Fprintf(out, "validating the directory %s with %s -C ...\n", *dir, checker.Describe())
	if err := checker.CheckDirectory(ctx, *dir); err != nil {
		return err
	}
	fmt.Fprintln(out, "ok")
	return nil
}

func runUp(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("up", out)
	dir := fs.String("dir", "/etc/sing-box", "directory holding the generated docker-compose.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	composePath := filepath.Join(*dir, deploy.ComposeFileName)
	if _, err := os.Stat(composePath); err != nil {
		return fmt.Errorf("no compose project at %s: run `spaiter-vpn init -out %s` first", composePath, *dir)
	}

	// Delegate to docker compose rather than reimplementing it: the compose
	// file is the source of truth for the container's lifecycle, and an
	// installer that starts containers behind compose's back leaves an
	// unmanaged container that the next `compose up` will not reconcile.
	runner, err := compose.Detect(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "running %s compose -f %s up -d\n", runner.DisplayName(), composePath)
	if err := runner.Up(ctx, composePath, out, os.Stderr); err != nil {
		return fmt.Errorf("docker compose up failed: %w", err)
	}
	fmt.Fprintln(out, "\nNext: spaiter-vpn selftest")
	return nil
}
