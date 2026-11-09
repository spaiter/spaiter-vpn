// Package selftest proves, against the running server, that BitTorrent
// traffic is detected and rejected.
//
// This is a product feature rather than a test suite: neither Hiddify nor
// 3x-ui ships anything equivalent, and a unit test passing says nothing about
// the instance an operator just deployed. It takes a few seconds, touches no
// live endpoint, and involves no public swarm and no third party — the
// detection fires on the payload, so the datagrams are addressed to the test
// tunnel itself and never leave the host.
package selftest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/option"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/spaiter/spaiter-vpn/internal/corelog"
	"github.com/spaiter/spaiter-vpn/internal/hostinfo"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// Options configures a run.
type Options struct {
	// ConfigPath is the running instance's config.json on the host.
	ConfigPath string
	// LogPath overrides where the log is read from. Empty means "beside the
	// config", which is where the container mount puts it.
	LogPath string
	// Controller and Secret override what the config says about the clash API.
	Controller string
	Secret     string

	// Tag, Port, Subnet and Interface describe the throwaway endpoint. The
	// defaults are chosen to collide with nothing.
	Tag    string
	Port   uint16
	Subnet netip.Prefix
	// AutoSubnet replaces Subnet with the first non-overlapping private /24
	// when the preferred default is already used by a production endpoint.
	// An explicitly selected CLI subnet disables this fallback and still fails
	// closed on a collision.
	AutoSubnet bool
	Interface  string
	MTU        int

	// SettleDelay is how long to wait after the last datagram before reading
	// the log. The sniffer has a 100 ms timeout per connection, so this only
	// has to cover writing the line out.
	SettleDelay time.Duration
	// HandshakeTimeout bounds the wait for the tunnel to come up.
	HandshakeTimeout time.Duration
}

// DefaultOptions returns the standard run.
func DefaultOptions() Options {
	return Options{
		ConfigPath:       "/etc/sing-box/config.json",
		Tag:              "bt-selftest-in",
		Port:             10899,
		Subnet:           netip.MustParsePrefix("10.99.0.0/24"),
		AutoSubnet:       true,
		Interface:        "bt-selftest",
		MTU:              1280,
		SettleDelay:      2 * time.Second,
		HandshakeTimeout: 15 * time.Second,
	}
}

// Result summarises a run.
type Result struct {
	Detections []corelog.Detection
	Rejections []string
	// RouteDecisionsLogged is whether the deployment's log level can show the
	// reject that follows a detection.
	RouteDecisionsLogged bool
	// LogLevel is the level the deployment is configured with.
	LogLevel string
	// LocalPeerSkipped records the "XDP: skipping local peer endpoint" line.
	// Its presence is a pass, not a failure: the fork refuses to ban a
	// loopback peer, and seeing the line proves the blocker resolved the
	// tunnel address back to the peer's real endpoint.
	LocalPeerSkipped bool
	LogLines         int
}

// Run performs the self-test, writing progress to out.
func Run(ctx context.Context, out io.Writer, opts Options) (*Result, error) {
	live, err := ReadLiveConfig(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if opts.AutoSubnet {
		opts.Subnet, err = chooseTestSubnet(live, opts.Subnet)
		if err != nil {
			return nil, err
		}
	}

	logPath := opts.LogPath
	if logPath == "" {
		if logPath, err = live.HostLogPath(); err != nil {
			return nil, err
		}
	}
	controller := firstNonEmpty(opts.Controller, live.ClashAPIController)
	secret := firstNonEmpty(opts.Secret, live.ClashAPISecret)
	client, err := manage.New(controller, secret)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "config:     %s\n", live.Path)
	fmt.Fprintf(out, "log:        %s\n", logPath)
	fmt.Fprintf(out, "clash API:  %s\n", controller)

	if err := checkTestResourcesAreFree(live, opts); err != nil {
		return nil, err
	}

	// Record which production endpoints are listening before anything is
	// touched, so "apply disturbed nothing" is an assertion rather than a hope.
	portsBefore, err := hostinfo.ListeningUDPPorts()
	if err != nil {
		return nil, err
	}
	liveTags := sortedTags(live.EndpointPorts)
	for _, tag := range liveTags {
		if !portsBefore[live.EndpointPorts[tag]] {
			fmt.Fprintf(out, "note:       %s (port %d) was already not listening before the test\n", tag, live.EndpointPorts[tag])
		}
	}

	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate test endpoint key: %w", err)
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate test client key: %w", err)
	}

	serverAddr := netip.PrefixFrom(opts.Subnet.Masked().Addr().Next(), opts.Subnet.Bits())
	clientAddr := netip.PrefixFrom(serverAddr.Addr().Next(), opts.Subnet.Bits())

	fmt.Fprintf(out, "\n1. creating endpoint %s on port %d (%s)\n", opts.Tag, opts.Port, opts.Subnet)
	endpoint := testEndpoint(opts, serverKey, clientKey, serverAddr, clientAddr)
	if err := client.AddEndpoint(ctx, endpoint); err != nil {
		return nil, fmt.Errorf("add test endpoint: %w", err)
	}

	// From here the endpoint exists in the config file and must be removed
	// whatever happens, including on a context cancellation.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := cleanup(cleanupCtx, out, client, opts, live); err != nil {
			fmt.Fprintf(out, "\nCLEANUP FAILED: %v\n", err)
			fmt.Fprintf(out, "The test endpoint may still be in %s. Remove it with:\n", live.Path)
			fmt.Fprintf(out, "  DELETE /manage/endpoints/%s  then  POST /manage/apply\n", opts.Tag)
		}
	}()

	applied, err := client.Apply(ctx)
	if err != nil {
		return nil, fmt.Errorf("apply test endpoint: %w", err)
	}
	if err := assertOnlyAdded(applied, opts.Tag); err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "   applied: added=%v, nothing recreated or reloaded\n", applied.Endpoints.Added)

	portsAfter, err := hostinfo.ListeningUDPPorts()
	if err != nil {
		return nil, err
	}
	for _, tag := range liveTags {
		port := live.EndpointPorts[tag]
		if portsBefore[port] && !portsAfter[port] {
			return nil, fmt.Errorf("production endpoint %s stopped listening on port %d after the apply; the test has disturbed live traffic", tag, port)
		}
	}
	if !portsAfter[opts.Port] {
		return nil, fmt.Errorf("the test endpoint is not listening on port %d after apply, so nothing was actually started", opts.Port)
	}
	fmt.Fprintf(out, "   %d production endpoints still listening\n", len(liveTags))

	fmt.Fprintf(out, "\n2. bringing up %s (%s -> 127.0.0.1:%d)\n", opts.Interface, clientAddr, opts.Port)
	tunnel, err := createTunnel(TunnelConfig{
		Name:            opts.Interface,
		MTU:             opts.MTU,
		PrivateKey:      clientKey,
		ServerPublicKey: serverKey.PublicKey(),
		ServerEndpoint:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(opts.Port)},
		Address:         clientAddr,
		AllowedIPs:      opts.Subnet,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := tunnel.Close(); err != nil {
			fmt.Fprintf(out, "\nwarning: could not remove %s: %v\n", opts.Interface, err)
		}
	}()

	if err := tunnel.WaitHandshake(ctx, opts.HandshakeTimeout); err != nil {
		return nil, fmt.Errorf("%w\n(the endpoint answers no ICMP on its own tunnel address, so the handshake is the only proof the tunnel works)", err)
	}
	fmt.Fprintln(out, "   handshake complete")

	probes, err := Probes()
	if err != nil {
		return nil, err
	}

	// Mark the log only now: everything above also logs, and a window that
	// starts earlier would pick up the endpoint's own startup lines.
	offset, err := corelog.Offset(logPath)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(out, "\n3. sending %d datagrams to %s\n", len(probes), serverAddr.Addr())
	for _, probe := range probes {
		destination := netip.AddrPortFrom(serverAddr.Addr(), probe.Port)
		if err := tunnel.Send(destination, probe.Payload); err != nil {
			return nil, fmt.Errorf("probe %q: %w", probe.Name, err)
		}
		expectation := "expect no detection"
		if probe.Detected() {
			expectation = "expect detector=" + probe.Detector
		}
		fmt.Fprintf(out, "   :%-5d %-32s %s\n", probe.Port, probe.Name, expectation)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(opts.SettleDelay):
	}

	fmt.Fprintf(out, "\n4. reading %s from offset %d\n", logPath, offset)
	slice, err := corelog.ReadSince(logPath, offset)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Detections:           slice.Detections(),
		Rejections:           slice.Rejections(),
		RouteDecisionsLogged: live.RouteDecisionsAreLogged(),
		LogLevel:             live.LogLevel,
		LocalPeerSkipped:     slice.Contains("XDP: skipping local peer endpoint"),
		LogLines:             slice.Lines(),
	}
	if err := assertProbes(out, opts.Tag, probes, result); err != nil {
		return result, err
	}
	return result, nil
}

// assertProbes is where the run passes or fails.
func assertProbes(out io.Writer, tag string, probes []Probe, result *Result) error {
	byPort := map[uint16][]corelog.Detection{}
	for _, d := range result.Detections {
		if d.Inbound != tag {
			// A detection from a real client happening to land in the same
			// window. Not ours, and not a result.
			continue
		}
		byPort[d.DestinationPort] = append(byPort[d.DestinationPort], d)
	}

	fmt.Fprintf(out, "   %d log lines, %d detections on %s\n", result.LogLines, countDetections(byPort), tag)

	var problems []string
	seenDetector := map[string]uint16{}
	for _, probe := range probes {
		found := byPort[probe.Port]
		switch {
		case !probe.Detected() && len(found) > 0:
			problems = append(problems, fmt.Sprintf(
				"control datagram on port %d was flagged as bittorrent (detector=%s); the sniffer has a false positive, so the other results cannot be trusted",
				probe.Port, found[0].Detector))
		case !probe.Detected():
			fmt.Fprintf(out, "   PASS  :%-5d %-32s not detected, as required\n", probe.Port, probe.Name)
		case len(found) == 0:
			problems = append(problems, fmt.Sprintf(
				"no detection for %s on port %d (expected detector=%s)", probe.Name, probe.Port, probe.Detector))
		case found[0].Detector != probe.Detector:
			problems = append(problems, fmt.Sprintf(
				"%s on port %d was detected as %q, expected %q", probe.Name, probe.Port, found[0].Detector, probe.Detector))
		default:
			if other, dup := seenDetector[found[0].Detector]; dup {
				problems = append(problems, fmt.Sprintf(
					"detector %q fired for both port %d and port %d; three distinct detectors were expected, so one of them is a catch-all",
					found[0].Detector, other, probe.Port))
			}
			seenDetector[found[0].Detector] = probe.Port
			fmt.Fprintf(out, "   PASS  :%-5d %-32s detector=%s\n", probe.Port, probe.Name, found[0].Detector)
		}
	}

	// A detection that is not acted on is a log message, not a defence — but
	// "not acted on" and "not observable" are different claims, and conflating
	// them produces a frightening and false report. The router logs the reject
	// at debug while the detection is logged at info, so on an info-level
	// deployment the traffic IS dropped and there is simply no line to read.
	switch {
	case len(result.Rejections) > 0:
		fmt.Fprintf(out, "   PASS  reject actions: %s\n", strings.Join(unique(result.Rejections), ", "))
	case !result.RouteDecisionsLogged:
		problems = append(problems, fmt.Sprintf(
			"enforcement cannot be proved at log level %q: the detection is logged at info but the reject that follows it is logged at debug, "+
				"so this run shows the traffic was identified and shows nothing about what happened next. "+
				"Set log.level to debug (or trace) and run this again; do not read this as traffic having been allowed through",
			firstNonEmpty(result.LogLevel, "info")))
	default:
		problems = append(problems, "the detections were logged but no reject action was recorded; traffic was identified and then allowed through")
	}
	if result.LocalPeerSkipped {
		fmt.Fprintln(out, "   note  XDP skipped the loopback peer, as it must; the ban itself cannot be exercised from localhost")
	}

	if len(problems) > 0 {
		return fmt.Errorf("self-test failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func cleanup(ctx context.Context, out io.Writer, client *manage.Client, opts Options, live *LiveConfig) error {
	fmt.Fprintf(out, "\n5. removing %s\n", opts.Tag)
	if err := client.DeleteEndpoint(ctx, opts.Tag); err != nil {
		return fmt.Errorf("delete endpoint: %w", err)
	}
	applied, err := client.Apply(ctx)
	if err != nil {
		return fmt.Errorf("apply the removal: %w", err)
	}
	if !containsString(applied.Endpoints.Removed, opts.Tag) {
		return fmt.Errorf("apply did not report %s as removed: %+v", opts.Tag, applied.Endpoints)
	}

	// sing-box rewrites config.json itself through config_output_path, so the
	// authoritative check that the tag is gone is the file, not the API.
	mentioned, err := MentionsTag(live.Path, opts.Tag)
	if err != nil {
		return err
	}
	if mentioned {
		return fmt.Errorf("%s still mentions %s after the removal was applied", live.Path, opts.Tag)
	}
	fmt.Fprintf(out, "   removed, and %s no longer mentions it\n", live.Path)

	ports, err := hostinfo.ListeningUDPPorts()
	if err != nil {
		return err
	}
	if ports[opts.Port] {
		return fmt.Errorf("port %d is still bound after the endpoint was removed", opts.Port)
	}
	var missing []string
	for _, tag := range sortedTags(live.EndpointPorts) {
		if !ports[live.EndpointPorts[tag]] {
			missing = append(missing, fmt.Sprintf("%s (%d)", tag, live.EndpointPorts[tag]))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("these production endpoints are not listening after cleanup: %s", strings.Join(missing, ", "))
	}
	fmt.Fprintln(out, "   production endpoints verified listening")
	return nil
}

// checkTestResourcesAreFree refuses to start if the throwaway names or
// addresses are already in use, rather than colliding with live state.
func checkTestResourcesAreFree(live *LiveConfig, opts Options) error {
	if _, exists := live.EndpointPorts[opts.Tag]; exists {
		return fmt.Errorf("the config already has an endpoint tagged %s; a previous run did not clean up", opts.Tag)
	}
	for tag, port := range live.EndpointPorts {
		if port == opts.Port {
			return fmt.Errorf("port %d is already used by endpoint %s; pass a different test port", opts.Port, tag)
		}
	}
	for _, addr := range live.EndpointAddresses {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			continue
		}
		if prefix.Overlaps(opts.Subnet) {
			return fmt.Errorf("test subnet %s overlaps endpoint address %s; pass a different test subnet", opts.Subnet, prefix)
		}
	}
	// Never route a routable prefix into the test tunnel: sing-box forwards
	// the packet out, the host route sends it straight back in, and it loops.
	// The test only ever addresses the tunnel's own endpoint, so the only
	// requirement here is that the subnet is private.
	if !opts.Subnet.Addr().IsPrivate() {
		return fmt.Errorf("test subnet %s is not private; routing a routable prefix into the test tunnel makes packets loop between sing-box and the host", opts.Subnet)
	}
	if opts.Subnet.Bits() > 29 {
		return fmt.Errorf("test subnet %s is too small for an endpoint and a client", opts.Subnet)
	}
	return nil
}

func chooseTestSubnet(live *LiveConfig, preferred netip.Prefix) (netip.Prefix, error) {
	if subnetDoesNotOverlap(live, preferred) {
		return preferred, nil
	}
	// Keep the historical 10.99.0.0/24 as the first choice, then walk down a
	// deterministic part of RFC1918 space. Bootstrap profiles use only a few
	// /24s, so this leaves ample room without introducing a random route into
	// a proof whose output should be reproducible.
	for second := 98; second >= 1; second-- {
		candidate := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(second), 0, 0}), 24)
		if subnetDoesNotOverlap(live, candidate) {
			return candidate, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no free automatic self-test subnet remains in 10.1.0.0/24 through 10.99.0.0/24; pass -subnet explicitly")
}

func subnetDoesNotOverlap(live *LiveConfig, candidate netip.Prefix) bool {
	for _, text := range live.EndpointAddresses {
		prefix, err := netip.ParsePrefix(text)
		if err == nil && prefix.Overlaps(candidate) {
			return false
		}
	}
	return true
}

func testEndpoint(opts Options, serverKey, clientKey wgtypes.Key, serverAddr, clientAddr netip.Prefix) option.Endpoint {
	return option.Endpoint{
		Type: C.TypeAwg,
		Tag:  opts.Tag,
		Options: &option.AwgEndpointOptions{
			// No AmneziaWG parameters: plain WireGuard is what the host's own
			// wg(4) can speak, which is what makes the client side possible
			// without any fork-specific userspace.
			UseIntegratedTun: false,
			PrivateKey:       serverKey.String(),
			Address:          badoption.Listable[netip.Prefix]{serverAddr},
			MTU:              uint32(opts.MTU),
			ListenPort:       opts.Port,
			Peers: []option.AwgPeerOptions{{
				Name:       "selftest",
				PublicKey:  clientKey.PublicKey().String(),
				AllowedIPs: badoption.Listable[netip.Prefix]{netip.PrefixFrom(clientAddr.Addr(), 32)},
			}},
		},
	}
}

// assertOnlyAdded is the check that the apply left live traffic alone.
func assertOnlyAdded(applied *manage.ApplyResult, tag string) error {
	if !containsString(applied.Endpoints.Added, tag) {
		return fmt.Errorf("apply did not add %s: %+v", tag, applied.Endpoints)
	}
	if len(applied.Endpoints.Recreated) > 0 {
		return fmt.Errorf("apply recreated endpoints %v, dropping their sessions; the test must not disturb live traffic", applied.Endpoints.Recreated)
	}
	if len(applied.Endpoints.Reloaded) > 0 {
		return fmt.Errorf("apply reloaded endpoints %v; adding a new endpoint should touch nothing else", applied.Endpoints.Reloaded)
	}
	if len(applied.Inbounds.Recreated) > 0 || len(applied.Inbounds.Reloaded) > 0 || len(applied.Inbounds.Added) > 0 {
		return fmt.Errorf("apply changed inbounds %+v; the test only adds an endpoint", applied.Inbounds)
	}
	return nil
}

func countDetections(byPort map[uint16][]corelog.Detection) int {
	total := 0
	for _, list := range byPort {
		total += len(list)
	}
	return total
}

func sortedTags(m map[string]uint16) []string {
	out := make([]string, 0, len(m))
	for tag := range m {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func unique(list []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range list {
		if _, dup := seen[item]; dup {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
