package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

func runPreflight(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("preflight", out)
	dir := fs.String("out", "/etc/sing-box", "directory the deployment will be written to")
	cacheDir := fs.String("cache-dir", "", "host directory mounted at /var/lib/sing-box (default: <out>/../cache)")
	users := fs.String("users", "preflight", "client names, only to size the deployment being checked")
	// The Tier B flags matter more here than anywhere else: this is the
	// command someone runs *before* installing, and whether a given
	// certificate source can work at all is a property of the host. Without
	// these, `preflight` silently reports on a Tier A deployment and says
	// nothing about the thing most likely to stop a Tier B one.
	tier := fs.String("tier", string(profile.TierA), "which protocols to check for: a or ab")
	domain := fs.String("domain", "", "domain for the Tier B protocols; checked for resolution")
	certSource := fs.String("cert-source", "", "certificate source to check the prerequisites of: files, acme-http or acme-dns")
	certFile := fs.String("cert-file", "", "certificate chain, for -cert-source=files")
	keyFile := fs.String("key-file", "", "private key, for -cert-source=files")
	acmeDataDir := fs.String("acme-data-dir", "", "where the ACME state will persist (default: "+profile.ACMEDefaultDataDirectory+")")
	acmeHTTPPort := fs.Uint("acme-http-port", 0, "alternative HTTP-01 port to check instead of 80")
	dnsProvider := fs.String("dns-provider", "", "DNS-01 provider, for -cert-source=acme-dns")
	disable := fs.String("disable", "", "comma-separated protocol tags to leave out")
	ports := fs.String("ports", "", "override ports as tag=port[,tag=port]")
	xdpInterfaces := fs.String("xdp-interface", "", "host interfaces for the XDP blocker (default: the default-route interface; \"none\" disables it)")
	logLevel := fs.String("log-level", "", "the log level the deployment will use; raises the log-rotation check to a failure at debug or trace")
	image := fs.String("image", singbox.DefaultImage, "sing-box container image")
	binary := fs.String("sing-box", "", "path to a local sing-box binary instead of the image")
	forSelftest := fs.Bool("selftest", false, "also check what the self-test needs")
	strict := fs.Bool("strict", false, "exit non-zero on warnings and unknowns too")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn preflight [flags]\n\n")
		fmt.Fprintf(out, "Checks the host facts that actually break this deployment, before anything\n")
		fmt.Fprintf(out, "is written or started: port conflicts, whether XDP can load at all on this\n")
		fmt.Fprintf(out, "kernel, and whether a :: listener will serve IPv4 clients.\n\n")
		fmt.Fprintf(out, "Severities: FAIL stops the deployment, WARN is something to know, and ? is\n")
		fmt.Fprintf(out, "a check that could not reach an answer — reported apart from WARN because\n")
		fmt.Fprintf(out, "\"cannot tell\" and \"imperfect but fine\" deserve different reactions.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	spec, err := specFromFlags(initFlags{
		users:         *users,
		tier:          *tier,
		domain:        *domain,
		certSource:    *certSource,
		certFile:      *certFile,
		keyFile:       *keyFile,
		acmeDataDir:   *acmeDataDir,
		acmeHTTPPort:  *acmeHTTPPort,
		dnsProvider:   *dnsProvider,
		disable:       *disable,
		ports:         *ports,
		xdpInterfaces: *xdpInterfaces,
		logLevel:      *logLevel,
		checkOnly:     true,
	})
	if err != nil {
		return err
	}

	report := preflight.Run(ctx, preflight.Options{
		Spec:          spec,
		ConfigDir:     *dir,
		CacheDir:      resolveCacheDir(*dir, *cacheDir),
		Image:         *image,
		SingBoxBinary: *binary,
		ForSelftest:   *forSelftest,
	})
	report.Write(out)
	return report.Err(*strict)
}

// resolveCacheDir mirrors what init does, so preflight checks the directories
// init will actually use rather than a different pair.
func resolveCacheDir(outDir, cacheDir string) string {
	if cacheDir != "" {
		return cacheDir
	}
	return filepath.Join(filepath.Dir(filepath.Clean(outDir)), "cache")
}
