package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/control"
	"github.com/spaiter/spaiter-vpn/internal/web"
)

const defaultWebKey = "/etc/spaiter-vpn/web.key"

func runWeb(ctx context.Context, out io.Writer, args []string) error {
	subcommands := map[string]func(context.Context, io.Writer, []string) error{
		"serve":      runWebServe,
		"key":        runWebKey,
		"login-link": runWebLoginLink,
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" {
		fmt.Fprintln(out, "usage: spaiter-vpn web <serve|key|login-link> [flags]")
		fmt.Fprintln(out, "\nThe browser front end of the control daemon. It holds no privilege: every")
		fmt.Fprintln(out, "change is a control request whose plan is shown before it is applied.")
		fmt.Fprintln(out, "\n  key         create the key that signs login links")
		fmt.Fprintln(out, "  login-link  print a one-time login link")
		fmt.Fprintln(out, "  serve       run the server (loopback by default; publish it behind HTTPS)")
		if len(args) == 0 {
			return ErrUsage
		}
		return nil
	}
	run, ok := subcommands[args[0]]
	if !ok {
		return fmt.Errorf("%w: unknown web subcommand %q", ErrUsage, args[0])
	}
	return run(ctx, out, args[1:])
}

func runWebKey(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("web key", out)
	path := fs.String("key", defaultWebKey, "where to write the key")
	group := fs.Int("group", -1, "gid allowed to read it (the web server's and the bot's), mode 0640")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := web.NewKey()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s (an existing key is never replaced; remove it first to invalidate every link): %w", *path, err)
	}
	if _, err := file.WriteString(key); err != nil {
		file.Close()
		return err
	}
	if *group >= 0 {
		if err := file.Chown(-1, *group); err != nil {
			file.Close()
			return err
		}
		if err := file.Chmod(0o640); err != nil {
			file.Close()
			return err
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", *path)
	return nil
}

func runWebLoginLink(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("web login-link", out)
	path := fs.String("key", defaultWebKey, "the key that signs login links")
	base := fs.String("url", "http://127.0.0.1:10880", "the address the web UI is reached at")
	ttl := fs.Duration("ttl", 10*time.Minute, "how long the link stays valid (at most 24h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ttl <= 0 || *ttl > 24*time.Hour {
		return fmt.Errorf("%w: -ttl must be between 1s and 24h", ErrUsage)
	}
	key, err := web.LoadKey(*path)
	if err != nil {
		return err
	}
	token, err := web.LoginToken(key, time.Now().Add(*ttl))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s/login?token=%s\n", strings.TrimRight(*base, "/"), token)
	return nil
}

func runWebServe(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("web serve", out)
	listen := fs.String("listen", "127.0.0.1:10880", "address to listen on")
	socket := fs.String("socket", defaultControlSocket, "control daemon socket")
	path := fs.String("key", defaultWebKey, "the key that signs login links")
	secure := fs.Bool("secure-cookie", false, "mark the session cookie Secure; set when served over HTTPS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("the web server needs no privilege; run it as an account listed in the control daemon's allow-list, not as root")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("%w: -listen: %v", ErrUsage, err)
	}
	if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && !*secure {
		return fmt.Errorf("%w: listening beyond loopback needs HTTPS in front and -secure-cookie", ErrUsage)
	}
	key, err := web.LoadKey(*path)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           (&web.Server{Control: control.Client{Socket: *socket}, Key: key, Secure: *secure}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintf(out, "web: listening on %s, control socket %s\n", *listen, *socket)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
