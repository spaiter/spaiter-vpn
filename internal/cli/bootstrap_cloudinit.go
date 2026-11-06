package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/cloudinit"
)

func runBootstrapCloudInit(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("bootstrap cloud-init", out)
	desiredPath := fs.String("f", "", "desired-state document for the new server")
	release := fs.String("release", "", "URL of the release directory (SHA256SUMS, SHA256SUMS.asc, the tarball)")
	version := fs.String("version", "", "release tag to install, such as v0.1.0")
	credentialDir := fs.String("credentials", "", "directory holding one file per credential the document names")
	signingKey := fs.String("signing-key", "", "armored public key that signed the release (default: the project's)")
	fingerprint := fs.String("fingerprint", "", "fingerprint -signing-key must have")
	output := fs.String("o", "", "where to write the user-data (default: stdout)")
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: spaiter-vpn bootstrap cloud-init -f desired.json -release URL -version vX [-credentials DIR] [-o user-data]")
		fmt.Fprintln(out, "\nRenders #cloud-config user-data for a fresh Ubuntu 24.04 or Debian 12/13 VPS:")
		fmt.Fprintln(out, "it downloads the release, checks the signature over SHA256SUMS against a")
		fmt.Fprintln(out, "pinned key and the tarball against SHA256SUMS, installs the binary, stores")
		fmt.Fprintln(out, "the credentials and applies the document. Nothing unverified is executed.")
		fmt.Fprintln(out, "\nThe user-data carries the document and every credential it names, and")
		fmt.Fprintln(out, "providers can read user-data. Prefer a bot without a token in it and")
		fmt.Fprintln(out, "rotate anything that must travel this way once the server is up.")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *desiredPath == "" || *release == "" || *version == "" || fs.NArg() != 0 {
		return fmt.Errorf("%w: cloud-init needs -f, -release and -version", ErrUsage)
	}
	desired, err := state.Load(*desiredPath)
	if err != nil {
		return err
	}
	if !desired.Bootstrap.InstallDocker {
		return fmt.Errorf("%w: a fresh VPS has no Docker; set bootstrap.installDocker to true in %s", ErrUsage, *desiredPath)
	}
	canonical, err := canonicalJSON(desired)
	if err != nil {
		return err
	}
	options := cloudinit.Options{
		Desired: canonical, ReleaseBase: *release, Version: *version,
		Credentials: map[string][]byte{},
		ClaimBot:    desired.Bot.Enabled && len(desired.Bot.AdminIDs) == 0,
	}
	for _, reference := range discover.CredentialRefs(desired) {
		if *credentialDir == "" {
			return fmt.Errorf("%w: the document needs credential %q; pass -credentials DIR", ErrUsage, reference)
		}
		data, err := os.ReadFile(filepath.Join(*credentialDir, string(reference)))
		if err != nil {
			return fmt.Errorf("read credential %s: %w", reference, err)
		}
		options.Credentials[string(reference)] = data
	}
	if *signingKey != "" {
		key, err := os.ReadFile(*signingKey)
		if err != nil {
			return err
		}
		options.SigningKey, options.Fingerprint = key, strings.ToUpper(*fingerprint)
	}
	userData, err := cloudinit.Render(options)
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = out.Write(userData)
		return err
	}
	if err := os.WriteFile(*output, userData, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (mode 0600: it holds credentials)\n", *output)
	if len(options.Credentials) > 0 {
		fmt.Fprintln(out, "warning: the provider can read user-data; rotate these credentials once the server is up")
	}
	return nil
}

func canonicalJSON(desired state.State) ([]byte, error) {
	canonical, err := desired.Canonical()
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
