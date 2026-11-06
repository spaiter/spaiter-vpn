package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/client"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

func runClients(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("clients", out)
	dir := fs.String("dir", "/etc/sing-box", "deployment directory written by `init`")
	secretsPath := fs.String("secrets", "", "secrets file (default: <dir>/secrets/secrets.json)")
	outDir := fs.String("out", "", "where to write the bundles (default: <dir>/clients)")
	host := fs.String("host", "", "public hostname or address clients dial (required)")
	cdnHost := fs.String("cdn-host", "", "hostname where the websocket inbound is reachable, if a CDN fronts it")
	cdnPort := fs.Uint("cdn-port", 443, "port of that CDN endpoint")
	fingerprint := fs.String("fingerprint", client.DefaultTLSFingerprint, "browser fingerprint uTLS imitates")
	image := fs.String("image", singbox.DefaultImage, "sing-box container image used to validate the result")
	binary := fs.String("sing-box", "", "local sing-box binary to validate with instead of the image")
	skipCheck := fs.Bool("skip-check", false, "do not validate the generated client configs")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn clients -host <public-address> [flags]\n\n")
		fmt.Fprintf(out, "Turns a deployment into something a person can connect with: a sing-box\n")
		fmt.Fprintf(out, "client config, share URLs for the protocols that have them, WireGuard\n")
		fmt.Fprintf(out, ".conf files, and a subscription file — one set per user.\n\n")
		fmt.Fprintf(out, "-host is required and cannot be guessed: the server binds wildcard\n")
		fmt.Fprintf(out, "addresses, so the address a client dials appears nowhere in its config.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("%w: -host is required; the server config binds wildcards, so the address clients dial cannot be derived from it", ErrUsage)
	}
	if *cdnPort > 65535 {
		return fmt.Errorf("%w: -cdn-port %d is not a port", ErrUsage, *cdnPort)
	}

	resolvedSecrets := *secretsPath
	if resolvedSecrets == "" {
		resolvedSecrets = filepath.Join(*dir, "secrets", "secrets.json")
	}
	raw, err := os.ReadFile(resolvedSecrets)
	if err != nil {
		return fmt.Errorf("read %s: %w", resolvedSecrets, err)
	}
	var secrets profile.Secrets
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return fmt.Errorf("parse %s: %w", resolvedSecrets, err)
	}

	// The spec is reconstructed from the secrets rather than re-derived from
	// flags: ports, subnets and handshake targets must match what was
	// actually deployed, and the secrets file is the only record of that which
	// travels with the deployment.
	spec, err := profile.SpecFromSecrets(secrets)
	if err != nil {
		return err
	}

	bundles, err := client.Generate(spec, secrets, client.Endpoint{
		Host:           *host,
		CDNHost:        *cdnHost,
		CDNPort:        uint16(*cdnPort),
		TLSFingerprint: *fingerprint,
	})
	if err != nil {
		return err
	}

	if !*skipCheck {
		if err := validateClientConfigs(ctx, out, bundles, *binary, *image); err != nil {
			return err
		}
	}

	target := *outDir
	if target == "" {
		target = filepath.Join(*dir, "clients")
	}
	for _, bundle := range bundles {
		userDir := filepath.Join(target, bundle.User)
		if err := os.MkdirAll(userDir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", userDir, err)
		}
		// 0600 throughout: every one of these files is a credential. A share
		// URL is not a hint about how to connect, it IS the way in.
		writes := map[string][]byte{
			"sing-box.json": bundle.SingBox,
		}
		if len(bundle.URLs) > 0 {
			writes["urls.txt"] = []byte(strings.Join(bundle.URLs, "\n") + "\n")
			writes["subscription.txt"] = bundle.Subscription
		}
		for p, conf := range bundle.WireGuard {
			writes[string(p)+".conf"] = []byte(conf)
		}
		for name, data := range writes {
			if err := config.Write(filepath.Join(userDir, name), data, 0o600); err != nil {
				return err
			}
		}
		fmt.Fprintf(out, "%s: %d files (%d share URLs, %d wireguard configs)\n",
			userDir, len(writes), len(bundle.URLs), len(bundle.WireGuard))
	}

	// Omissions are reported once rather than per user: they are a property of
	// the deployment, not of a person.
	if len(bundles) > 0 && len(bundles[0].Omitted) > 0 {
		fmt.Fprintf(out, "\nNot included, and why:\n")
		for _, o := range bundles[0].Omitted {
			fmt.Fprintf(out, "  %-16s %-20s %s\n", o.Protocol, o.Artifact, o.Reason)
		}
	}
	fmt.Fprintf(out, "\nThe sing-box config listens on 127.0.0.1:%d as an HTTP and SOCKS proxy.\n", client.LocalProxyPort)
	return nil
}

// validateClientConfigs runs the real binary over every generated client
// config.
//
// The same reasoning as for the server side: generating from the core's option
// structs guarantees the shape, not that the values are usable. A client config
// is checkable in exactly the same way, so there is no excuse for handing out
// one that was never parsed.
func validateClientConfigs(ctx context.Context, out io.Writer, bundles []client.Bundle, binary, image string) error {
	checker, err := singbox.Detect(ctx, binary, image)
	if err != nil {
		return fmt.Errorf("%w\n\nPass -skip-check to write client configs without validating them", err)
	}
	fmt.Fprintf(out, "validating %d client configs with %s ...\n", len(bundles), checker.Describe())
	for _, bundle := range bundles {
		if err := checker.Check(ctx, bundle.SingBox); err != nil {
			return fmt.Errorf("the client config for %s is not usable: %w\n\n%s", bundle.User, err, bundle.SingBox)
		}
	}
	fmt.Fprintln(out, "sing-box check: ok")
	return nil
}
