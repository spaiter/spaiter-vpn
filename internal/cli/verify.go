package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/singbox"
	"github.com/spaiter/spaiter-vpn/internal/verify"
)

// verifyRun is a seam so tests can report results without starting a core.
var verifyRun = verify.Run

// runVerify sends a real request through every node of a user's subscription
// bundle, with the core running as a client on this machine.
func runVerify(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("verify", out)
	bundlePath := fs.String("bundle", "", "the user's subscription bundle (spaiter-vpn bot guide -bundle-out)")
	image := fs.String("image", singbox.DefaultImage, "core image to run as the client")
	binary := fs.String("sing-box", "", "local core binary to run instead of the image")
	target := fs.String("url", "https://www.gstatic.com/generate_204", "what to fetch through each node")
	timeout := fs.Duration("timeout", 10*time.Second, "per node")
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: spaiter-vpn verify -bundle FILE [-image REF | -sing-box PATH]")
		fmt.Fprintln(out, "\nRuns the core as a headless client of the bundle (no TUN, no privilege) and")
		fmt.Fprintln(out, "fetches -url through every node, which is what a client would do. Run it")
		fmt.Fprintln(out, "from where clients connect from; on the server itself it takes the hairpin.")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || fs.NArg() != 0 {
		return fmt.Errorf("%w: verify needs -bundle", ErrUsage)
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	runner := verify.DockerRunner(*image)
	if *binary != "" {
		runner = verify.BinaryRunner(*binary)
	}
	results, err := verifyRun(ctx, bundle, runner, *target, *timeout)
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range results {
		if r.Skipped != "" {
			fmt.Fprintf(out, "SKIP  %-36s %-10s %s\n", r.Node, r.Type, r.Skipped)
			continue
		}
		if r.Error != "" {
			failed++
			fmt.Fprintf(out, "FAIL  %-36s %-10s %s\n", r.Node, r.Type, r.Error)
		} else {
			fmt.Fprintf(out, "PASS  %-36s %-10s %s\n", r.Node, r.Type, r.Delay)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d nodes failed", failed, len(results))
	}
	fmt.Fprintln(out, "\nevery node this core can run passed")
	return nil
}
