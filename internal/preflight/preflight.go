// Package preflight checks, before anything is written or started, the
// handful of host facts that actually break this deployment.
//
// The list is short on purpose. It is not a general health check: every entry
// is something observed to fail, or something whose failure is silent. The
// expensive kind of failure here is not a refusal — it is a deployment that
// comes up, looks healthy, and quietly does less than it claims: an XDP
// blocker that loads nowhere, or inbounds reachable over IPv6 only.
package preflight

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/hostinfo"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

// Severity grades a finding.
type Severity int

const (
	// Pass is a check that found what it wanted.
	Pass Severity = iota
	// Warn is a check that found something an operator should know but which
	// does not stop the deployment.
	Warn
	// Unknown is a check that could not determine the answer. It is reported
	// separately from Warn because "I could not tell" and "it is fine but
	// imperfect" call for different reactions.
	Unknown
	// Fail is a check whose finding means the deployment will not work as
	// configured.
	Fail
)

func (s Severity) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Unknown:
		return "?   "
	case Fail:
		return "FAIL"
	}
	return "????"
}

// Check is one finding.
type Check struct {
	Name     string
	Severity Severity
	// Detail is what was found.
	Detail string
	// Remedy is what to do about it, and is mandatory for Warn and Fail: a
	// refusal with no way forward is just an obstacle.
	Remedy string
}

// Report is the result of a run.
type Report struct {
	Checks []Check
}

// Options describes what the deployment intends to do, so the checks can be
// about that rather than about the host in the abstract.
type Options struct {
	// Spec is the deployment being prepared. Ports, listen addresses and XDP
	// interfaces are all read from it.
	Spec profile.Spec
	// ConfigDir and CacheDir are the directories that will be written.
	ConfigDir string
	CacheDir  string
	// Image is the container image that will be run.
	Image string
	// SingBoxBinary, when set, replaces the image.
	SingBoxBinary string
	// ForSelftest adds the checks that only the self-test needs.
	ForSelftest bool
	// OwnDeploymentRunning says this deployment is already running, so its own
	// listeners are not conflicts.
	//
	// Without it a converging apply can never pass its own preflight: the port
	// check sees every one of the deployment's ports bound — by the deployment
	// it is about to update — and calls them conflicts. Ports and the
	// management address cannot change in a convergence (that is a migration),
	// so a bound port here is evidence of the thing being converged rather than
	// something in the way of it.
	OwnDeploymentRunning bool
	// FirewallRulesWillBeAdded tells the firewall check that the caller is
	// about to open the missing rules itself.
	//
	// The same shape of defect as the rotation flag below, and found the same
	// way: on a host whose firewall is actually switched on, preflight reports
	// the deployment's ports as blocked — correctly, since nothing has opened
	// them yet — and fails the very apply whose next step opens them. It only
	// stayed hidden because the development host happened to have every rule
	// already present.
	FirewallRulesWillBeAdded bool
	// LogrotateWillBeInstalled tells the rotation check that the caller is
	// about to install the rotation itself.
	//
	// Without it, bootstrap cannot pass its own preflight: the check runs
	// before any host file is written, so it correctly reports that nothing
	// rotates the log — and at debug level that is a failure, which aborts the
	// very apply whose next step installs the rotation. The check's question is
	// "will this log be reclaimed", not "is the file already there".
	LogrotateWillBeInstalled bool
}

// sysctl is indirected so the IPv6 checks can be tested. They are the ones
// whose entire value is catching a failure that leaves no other trace, so
// "it compiles and returns PASS on this host" is not evidence that they fire.
var sysctl = hostinfo.Sysctl

// MinimumFreeBytes is the floor below which the deployment is refused. The
// image is roughly 150 MB and the debug-level log grows into the tens of
// megabytes, so this is deliberately not generous — it is the point at which
// things break rather than a recommendation.
const MinimumFreeBytes = 512 << 20

// ComfortableFreeBytes is the point below which a warning is worth printing.
const ComfortableFreeBytes = 2 << 30

// Run performs every applicable check.
func Run(ctx context.Context, opts Options) *Report {
	report := &Report{}
	report.add(checkPrivileges())
	report.add(checkDirectories(opts)...)
	report.add(checkPorts(opts.Spec, opts.OwnDeploymentRunning)...)
	report.add(checkManagementPort(opts.Spec, opts.OwnDeploymentRunning))
	report.add(checkIPv6Binding(opts.Spec)...)
	report.add(checkFirewall(opts.Spec, opts.FirewallRulesWillBeAdded)...)
	report.add(checkTierB(ctx, opts)...)
	report.add(checkLogRotation(opts)...)
	report.add(checkXDP(opts.Spec)...)
	report.add(checkRuntime(ctx, opts)...)
	if opts.ForSelftest {
		report.add(checkSelftestPrerequisites())
	}
	return report
}

func (r *Report) add(checks ...Check) {
	for _, c := range checks {
		if c.Name != "" {
			r.Checks = append(r.Checks, c)
		}
	}
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool { return r.Count(Fail) > 0 }

// Count returns how many checks have the given severity.
func (r *Report) Count(severity Severity) int {
	n := 0
	for _, c := range r.Checks {
		if c.Severity == severity {
			n++
		}
	}
	return n
}

// Write renders the report.
func (r *Report) Write(out io.Writer) {
	width := 0
	for _, c := range r.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	for _, c := range r.Checks {
		fmt.Fprintf(out, "%s  %-*s  %s\n", c.Severity, width, c.Name, c.Detail)
		if c.Remedy != "" && c.Severity != Pass {
			fmt.Fprintf(out, "      %-*s  → %s\n", width, "", c.Remedy)
		}
	}
	fmt.Fprintf(out, "\n%d passed, %d warnings, %d unknown, %d failed\n",
		r.Count(Pass), r.Count(Warn), r.Count(Unknown), r.Count(Fail))
}

// Err returns an error when the report should stop the operation. With strict
// set, warnings and unknowns count too.
func (r *Report) Err(strict bool) error {
	if r.Failed() {
		return fmt.Errorf("preflight failed: %d of %d checks", r.Count(Fail), len(r.Checks))
	}
	if strict && (r.Count(Warn) > 0 || r.Count(Unknown) > 0) {
		return fmt.Errorf("preflight is not clean and -strict was given: %d warnings, %d unknown",
			r.Count(Warn), r.Count(Unknown))
	}
	return nil
}

func checkPrivileges() Check {
	if os.Geteuid() == 0 {
		return Check{Name: "privileges", Severity: Pass, Detail: "running as root"}
	}
	return Check{
		Name:     "privileges",
		Severity: Warn,
		Detail:   fmt.Sprintf("running as uid %d", os.Geteuid()),
		Remedy:   "root is needed to write under /etc and, for the self-test, to create a WireGuard interface; generation itself does not need it",
	}
}

func checkDirectories(opts Options) []Check {
	var checks []Check
	for name, dir := range map[string]string{"config directory": opts.ConfigDir, "cache directory": opts.CacheDir} {
		if dir == "" {
			continue
		}
		if err := hostinfo.Writable(dir); err != nil {
			checks = append(checks, Check{
				Name:     name,
				Severity: Fail,
				Detail:   err.Error(),
				Remedy:   fmt.Sprintf("create %s with the right ownership, or choose another location", dir),
			})
			continue
		}
		free, err := hostinfo.FreeBytes(dir)
		if err != nil {
			checks = append(checks, Check{
				Name:     name,
				Severity: Unknown,
				Detail:   err.Error(),
				Remedy:   "check free space by hand",
			})
			continue
		}
		switch {
		case free < MinimumFreeBytes:
			checks = append(checks, Check{
				Name:     name,
				Severity: Fail,
				Detail:   fmt.Sprintf("%s writable, %s free", dir, hostinfo.HumanBytes(free)),
				Remedy:   fmt.Sprintf("free up space: the image is ~150 MB and the debug log grows, so below %s this will break", hostinfo.HumanBytes(MinimumFreeBytes)),
			})
		case free < ComfortableFreeBytes:
			checks = append(checks, Check{
				Name:     name,
				Severity: Warn,
				Detail:   fmt.Sprintf("%s writable, %s free", dir, hostinfo.HumanBytes(free)),
				Remedy:   "the debug-level log grows unbounded; consider rotating it or lowering the level",
			})
		default:
			checks = append(checks, Check{
				Name:     name,
				Severity: Pass,
				Detail:   fmt.Sprintf("%s writable, %s free", dir, hostinfo.HumanBytes(free)),
			})
		}
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	return checks
}

func checkPorts(spec profile.Spec, ownDeploymentRunning bool) []Check {
	tcp, tcpErr := hostinfo.ListeningTCPPorts()
	udp, udpErr := hostinfo.ListeningUDPPorts()
	if tcpErr != nil || udpErr != nil {
		err := tcpErr
		if err == nil {
			err = udpErr
		}
		return []Check{{
			Name:     "ports",
			Severity: Unknown,
			Detail:   fmt.Sprintf("cannot read the bound ports: %v", err),
			Remedy:   "check with `ss -lntu` that the configured ports are free",
		}}
	}

	bound := map[string]map[uint16]bool{"tcp": tcp, "udp": udp}
	var conflicts []string
	total := 0
	for _, p := range spec.EnabledProtocols() {
		port := spec.Ports[p]
		for _, network := range p.Networks() {
			total++
			if bound[network][port] {
				conflicts = append(conflicts, fmt.Sprintf("%s/%d (%s)", network, port, p))
			}
		}
	}
	if len(conflicts) == 0 {
		detail := fmt.Sprintf("all %d listeners free", total)
		if ownDeploymentRunning {
			// Worth saying out loud: on a converging apply an empty conflict
			// list means the deployment is NOT listening, which is a different
			// and more worrying result than a free port on a fresh host.
			detail = fmt.Sprintf("none of the %d listeners are bound, although this deployment is supposed to be running", total)
			return []Check{{Name: "ports", Severity: Warn, Detail: detail,
				Remedy: "check that the core is actually serving; a convergence cannot verify listeners it cannot see"}}
		}
		return []Check{{Name: "ports", Severity: Pass, Detail: detail}}
	}
	if ownDeploymentRunning {
		return []Check{{
			Name:     "ports",
			Severity: Pass,
			Detail:   fmt.Sprintf("%d of %d listeners bound by this deployment, as expected while converging it", len(conflicts), total),
		}}
	}
	return []Check{{
		Name:     "ports",
		Severity: Fail,
		Detail:   "already in use: " + strings.Join(conflicts, ", "),
		Remedy:   "stop whatever holds them, or move the deployment with -ports tag=port[,tag=port]",
	}}
}

// checkManagementPort checks the clash API listener.
//
// Not part of checkPorts, because this one is not a protocol: it is the
// loopback control channel. It still has to be free, and the failure when it is
// not is the kind this package exists for — the core refuses to bind it and
// exits, so the deployment "starts" and then is not there. Everything that
// manages it afterwards (the bot, the self-test, `bootstrap status`, every
// user provisioned from Telegram) speaks to this port, so a conflict takes the
// whole deployment out while the protocol ports all look fine.
func checkManagementPort(spec profile.Spec, ownDeploymentRunning bool) Check {
	const name = "management port"
	if spec.ClashAPIListen == "" {
		return Check{Name: name, Severity: Warn,
			Detail: "no clash API listener is configured",
			Remedy: "without it the bot, the self-test and bootstrap status have no way to reach the core"}
	}
	addrPort, err := netip.ParseAddrPort(spec.ClashAPIListen)
	if err != nil {
		// A bare ":9090" is valid in the config and means every interface; the
		// core binds it and callers dial loopback.
		_, portText, found := strings.Cut(spec.ClashAPIListen, ":")
		if !found {
			return Check{Name: name, Severity: Unknown,
				Detail: fmt.Sprintf("cannot read the clash API listener %q", spec.ClashAPIListen)}
		}
		port, convErr := strconv.ParseUint(portText, 10, 16)
		if convErr != nil {
			return Check{Name: name, Severity: Unknown,
				Detail: fmt.Sprintf("cannot read the clash API listener %q", spec.ClashAPIListen)}
		}
		addrPort = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port))
	}

	tcp, err := hostinfo.ListeningTCPPorts()
	if err != nil {
		return Check{Name: name, Severity: Unknown,
			Detail: fmt.Sprintf("cannot read the bound ports: %v", err),
			Remedy: fmt.Sprintf("check with `ss -lnt` that %d is free", addrPort.Port())}
	}
	if tcp[addrPort.Port()] && ownDeploymentRunning {
		return Check{Name: name, Severity: Pass,
			Detail: fmt.Sprintf("tcp/%d is bound by this deployment's clash API, as expected while converging it", addrPort.Port())}
	}
	if tcp[addrPort.Port()] {
		return Check{Name: name, Severity: Fail,
			Detail: fmt.Sprintf("tcp/%d is already in use, so the core cannot bind its management API", addrPort.Port()),
			Remedy: "stop whatever holds it; the core exits when this bind fails, which looks like a deployment that started and then vanished"}
	}
	return Check{Name: name, Severity: Pass,
		Detail: fmt.Sprintf("tcp/%d is free for the clash API", addrPort.Port())}
}

// checkIPv6Binding is the subtlest check here, and the reason the package
// exists at all.
//
// Every internet-facing inbound binds the IPv6 wildcard `::` and relies on the
// dual-stack behaviour of a v6 socket to serve IPv4 clients too. Two sysctls
// break that silently:
//
//   - net.ipv6.bindv6only=1 makes a `::` socket refuse IPv4 entirely, so the
//     server starts, logs nothing unusual, and is unreachable for every IPv4
//     client.
//   - disabling IPv6 outright makes the bind fail, which at least is loud.
//
// The first is the dangerous one: nothing in the logs says what happened.
func checkIPv6Binding(spec profile.Spec) []Check {
	if !spec.PublicListen.IsValid() || !isIPv6Unspecified(spec.PublicListen) {
		return []Check{{
			Name:     "ipv6 dual-stack",
			Severity: Pass,
			Detail:   fmt.Sprintf("inbounds bind %s, so dual-stack behaviour does not apply", spec.PublicListen),
		}}
	}

	disabled, err := sysctl("net.ipv6.conf.all.disable_ipv6")
	if err != nil {
		return []Check{{
			Name:     "ipv6 dual-stack",
			Severity: Fail,
			Detail:   "IPv6 appears to be compiled out of the kernel",
			Remedy:   fmt.Sprintf("the generated inbounds bind %s, which will fail; re-run init with an IPv4 listen address", spec.PublicListen),
		}}
	}
	if disabled == "1" {
		return []Check{{
			Name:     "ipv6 dual-stack",
			Severity: Fail,
			Detail:   "net.ipv6.conf.all.disable_ipv6=1",
			Remedy:   fmt.Sprintf("the inbounds bind %s and the bind will fail; either enable IPv6 or re-run init with an IPv4 listen address", spec.PublicListen),
		}}
	}

	bindv6only, err := sysctl("net.ipv6.bindv6only")
	if err != nil {
		return []Check{{
			Name:     "ipv6 dual-stack",
			Severity: Unknown,
			Detail:   fmt.Sprintf("cannot read net.ipv6.bindv6only: %v", err),
			Remedy:   "verify by hand that a `::` listener accepts IPv4 clients",
		}}
	}
	if bindv6only == "1" {
		return []Check{{
			Name:     "ipv6 dual-stack",
			Severity: Fail,
			Detail:   "net.ipv6.bindv6only=1",
			Remedy:   "set it to 0 (`sysctl -w net.ipv6.bindv6only=0`, and persist it) — otherwise the inbounds come up on IPv6 only and every IPv4 client fails with nothing in the log to say why",
		}}
	}
	return []Check{{
		Name:     "ipv6 dual-stack",
		Severity: Pass,
		Detail:   "net.ipv6.bindv6only=0, so a :: listener serves IPv4 too",
	}}
}

// checkLogRotation looks for the thing whose absence eventually fills the disk.
//
// The core has no rotation of its own and writes an append-only file, so at
// debug level the log grows without bound. The consequence is not a lost log —
// it is a full disk, and that takes the server down. The directory check
// already warns about free space; this says whether anything is going to
// reclaim it.
func checkLogRotation(opts Options) []Check {
	if opts.ConfigDir == "" {
		return nil
	}
	logPath := filepath.Join(opts.ConfigDir, "sing-box.log")
	covered, known := hostinfo.LogrotateCovers(logPath)
	switch {
	case !known:
		return []Check{{
			Name:     "log rotation",
			Severity: Unknown,
			Detail:   "/etc/logrotate.d is not readable",
			Remedy:   "confirm by hand that something rotates " + logPath + "; the core will not",
		}}
	case covered:
		return []Check{{
			Name:     "log rotation",
			Severity: Pass,
			Detail:   "a logrotate config covers " + logPath,
		}}
	case opts.LogrotateWillBeInstalled:
		return []Check{{
			Name:     "log rotation",
			Severity: Pass,
			Detail:   "nothing rotates " + logPath + " yet; this apply installs the rotation",
		}}
	default:
		severity := Warn
		detail := "nothing rotates " + logPath
		// At debug level this is not a tidiness matter but a countdown: the live
		// deployment reached 24 MB and 230,000 lines in weeks.
		if strings.EqualFold(opts.Spec.LogLevel, "debug") || strings.EqualFold(opts.Spec.LogLevel, "trace") {
			severity = Fail
			detail += ", and the log level is " + opts.Spec.LogLevel
		}
		return []Check{{
			Name:     "log rotation",
			Severity: severity,
			Detail:   detail,
			Remedy:   "cp " + filepath.Join(opts.ConfigDir, "logrotate.conf") + " /etc/logrotate.d/spaiter-vpn — the core never rotates its own log, and a full disk takes the server down",
		}}
	}
}

// checkFirewall answers the question a port-occupancy check cannot.
//
// `ports` asks whether a port is free to bind. An operator wants to know
// whether a client will reach it, and those are different questions with
// different answers: a port can be free locally and refused by the firewall in
// front of it. That failure is silent — the service starts, logs nothing
// unusual, and nobody can connect.
//
// What this still cannot tell you is whether the port is reachable from the
// internet. A cloud provider's firewall, a NAT, or an ISP sit outside the
// machine and are invisible from inside it. The remedy says so rather than
// implying a clean report means reachable.
func checkFirewall(spec profile.Spec, rulesWillBeAdded bool) []Check {
	rules := firewall.Rules(spec)
	if len(rules) == 0 {
		return []Check{{
			Name:     "firewall",
			Severity: Warn,
			Detail:   "this deployment exposes no internet-facing port",
			Remedy:   "every enabled protocol binds loopback or sits behind a front; check that is intended",
		}}
	}

	backend := firewall.Detect()
	statuses, err := backend.Check(rules)
	if err != nil {
		return []Check{{
			Name:     "firewall",
			Severity: Unknown,
			Detail:   fmt.Sprintf("%s found but not readable: %v", backend.Kind, err),
			Remedy:   "re-run as root, or check by hand that the deployment's ports are allowed",
		}}
	}

	var blocked, unknown []string
	for _, r := range rules {
		switch statuses[r.String()] {
		case firewall.Blocked:
			blocked = append(blocked, r.String())
		case firewall.Unknown:
			unknown = append(unknown, r.String())
		}
	}

	switch {
	case len(blocked) > 0 && rulesWillBeAdded && backend.Kind == firewall.UFW && backend.Active:
		// Narrowed to the backend the caller can actually write to. Saying "it
		// will be opened" about firewalld or a raw nftables ruleset would be a
		// promise nothing keeps, and the deployment would come up reachable by
		// nobody with a clean preflight behind it.
		return []Check{{
			Name:     "firewall",
			Severity: Pass,
			Detail:   fmt.Sprintf("%s does not allow %s yet; this apply opens them", backend.Kind, strings.Join(blocked, ", ")),
		}}
	case len(blocked) > 0:
		return []Check{{
			Name:     "firewall",
			Severity: Fail,
			Detail:   fmt.Sprintf("%s is active and does not allow: %s", backend.Kind, strings.Join(blocked, ", ")),
			Remedy:   "run the generated firewall.sh, or add the rules by hand; without them the service starts and nobody can reach it",
		}}
	case len(unknown) > 0:
		return []Check{{
			Name:     "firewall",
			Severity: Unknown,
			Detail:   fmt.Sprintf("%s cannot be read reliably for %d of %d ports", backend.Kind, len(unknown), len(rules)),
			Remedy:   "confirm by hand that these ports are permitted: " + strings.Join(unknown, ", "),
		}}
	default:
		// The caveat belongs in the detail, not the remedy: a passing check
		// prints no remedy, and "clean preflight means reachable" is the most
		// expensive thing an operator could conclude here.
		detail := fmt.Sprintf("%d ports permitted by %s — says nothing about reachability from the internet", len(rules), backend.Kind)
		if backend.Kind == firewall.None {
			detail = fmt.Sprintf("no host firewall found, so none of the %d ports is blocked locally — a cloud firewall would be invisible from here", len(rules))
		}
		return []Check{{
			Name:     "firewall",
			Severity: Pass,
			Detail:   detail,
			Remedy:   "a cloud provider's firewall or a NAT sits outside this machine; verify with `spaiter-vpn probe -host … ` run from somewhere else",
		}}
	}
}

func checkXDP(spec profile.Spec) []Check {
	if len(spec.XDPInterfaces) == 0 {
		return []Check{{
			Name:     "xdp blocker",
			Severity: Warn,
			Detail:   "disabled in this configuration",
			Remedy:   "without it a BitTorrent detection drops the connection but never bans the client, so the same client simply reconnects",
		}}
	}

	var checks []Check

	virt := hostinfo.DetectVirtualization()
	if virt.Container {
		checks = append(checks, Check{
			Name:     "xdp kernel",
			Severity: Fail,
			Detail:   fmt.Sprintf("this is a %s container (%s), which shares the host kernel", virt.Kind, virt.Source),
			Remedy:   "XDP programs cannot be loaded from a shared-kernel guest; re-run init with -xdp-interface none and accept detection without banning, or move to a KVM-class VPS",
		})
	} else {
		detail := fmt.Sprintf("%s (%s)", virt.Kind, virt.Source)
		severity := Pass
		if virt.Kind == "unknown" {
			severity = Unknown
			detail = "could not determine the virtualisation type"
		}
		checks = append(checks, Check{
			Name:     "xdp kernel",
			Severity: severity,
			Detail:   detail,
			Remedy:   "if this host is an OpenVZ or LXC guest, XDP will not load; verify before relying on the ban",
		})
	}

	config, err := hostinfo.ReadKernelConfig()
	switch {
	case err != nil || !config.Available:
		checks = append(checks, Check{
			Name:     "xdp bpf support",
			Severity: Unknown,
			Detail:   "the running kernel's config is not readable",
			Remedy:   "confirm CONFIG_BPF_SYSCALL=y by hand; the deployment will still start either way, but the blocker may not attach",
		})
	case !config.Enabled("CONFIG_BPF_SYSCALL"):
		checks = append(checks, Check{
			Name:     "xdp bpf support",
			Severity: Fail,
			Detail:   "CONFIG_BPF_SYSCALL is not enabled in " + config.Source,
			Remedy:   "this kernel cannot load eBPF at all; re-run init with -xdp-interface none",
		})
	default:
		missing := []string{}
		for _, option := range []string{"CONFIG_BPF_JIT", "CONFIG_XDP_SOCKETS"} {
			if !config.Enabled(option) {
				missing = append(missing, option)
			}
		}
		if len(missing) > 0 {
			checks = append(checks, Check{
				Name:     "xdp bpf support",
				Severity: Warn,
				Detail:   "CONFIG_BPF_SYSCALL=y but " + strings.Join(missing, ", ") + " missing",
				Remedy:   "the blocker may attach with reduced performance, or not at all; test with the self-test from a non-loopback client",
			})
		} else {
			checks = append(checks, Check{
				Name:     "xdp bpf support",
				Severity: Pass,
				Detail:   "BPF syscall, JIT and XDP sockets all enabled",
			})
		}
	}

	if !hostinfo.BTFAvailable() {
		checks = append(checks, Check{
			Name:     "xdp btf",
			Severity: Warn,
			Detail:   "/sys/kernel/btf/vmlinux is absent",
			Remedy:   "CO-RE relocations need kernel BTF; if the blocker fails to load, this is the first thing to check",
		})
	} else {
		checks = append(checks, Check{Name: "xdp btf", Severity: Pass, Detail: "kernel BTF present"})
	}

	if !hostinfo.BPFFilesystemMounted() {
		checks = append(checks, Check{
			Name:     "bpffs",
			Severity: Warn,
			Detail:   "no bpf filesystem mounted",
			Remedy:   "mount it with `mount -t bpf bpf /sys/fs/bpf` if the blocker needs to pin maps",
		})
	} else {
		checks = append(checks, Check{Name: "bpffs", Severity: Pass, Detail: "mounted"})
	}

	checks = append(checks, checkXDPInterfaces(spec.XDPInterfaces)...)
	return checks
}

func checkXDPInterfaces(names []string) []Check {
	var checks []Check
	defaultIface, defaultErr := hostinfo.DefaultRouteInterface()

	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			checks = append(checks, Check{
				Name:     "xdp interface " + name,
				Severity: Fail,
				Detail:   "no such interface",
				Remedy:   "name an interface that exists; a program attached nowhere loads cleanly and sees no traffic",
			})
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			checks = append(checks, Check{
				Name:     "xdp interface " + name,
				Severity: Warn,
				Detail:   "interface is down",
				Remedy:   "bring it up, or attach to the interface that actually carries client traffic",
			})
			continue
		}
		if defaultErr == nil && name != defaultIface {
			checks = append(checks, Check{
				Name:     "xdp interface " + name,
				Severity: Warn,
				Detail:   fmt.Sprintf("up, but the default route is on %s", defaultIface),
				Remedy:   "client traffic arrives on the interface carrying the default route; confirm this is deliberate",
			})
			continue
		}
		checks = append(checks, Check{
			Name:     "xdp interface " + name,
			Severity: Pass,
			Detail:   "up, carries the default route",
		})
	}
	return checks
}

func checkRuntime(ctx context.Context, opts Options) []Check {
	if opts.SingBoxBinary != "" {
		if _, err := exec.LookPath(opts.SingBoxBinary); err != nil {
			return []Check{{
				Name:     "sing-box binary",
				Severity: Fail,
				Detail:   err.Error(),
				Remedy:   "point -sing-box at an executable, or drop the flag to use the container image",
			}}
		}
		return []Check{{Name: "sing-box binary", Severity: Pass, Detail: opts.SingBoxBinary}}
	}

	checker, err := singbox.Detect(ctx, "", opts.Image)
	if err != nil {
		return []Check{{
			Name:     "container runtime",
			Severity: Fail,
			Detail:   err.Error(),
			Remedy:   "install Docker and make sure the daemon is reachable, or pass -sing-box with a local binary",
		}}
	}
	checks := []Check{{Name: "container runtime", Severity: Pass, Detail: checker.Describe()}}

	if len(checker.Docker) > 0 {
		args := append(append([]string{}, checker.Docker[1:]...), "compose", "version", "--short")
		if err := exec.CommandContext(ctx, checker.Docker[0], args...).Run(); err != nil {
			checks = append(checks, Check{
				Name:     "docker compose",
				Severity: Fail,
				Detail:   "the compose plugin is not available",
				Remedy:   "install docker-compose-plugin; `spaiter-vpn up` delegates to it rather than starting containers behind its back",
			})
		} else {
			checks = append(checks, Check{Name: "docker compose", Severity: Pass, Detail: "plugin available"})
		}

		image := opts.Image
		if image == "" {
			image = singbox.DefaultImage
		}
		inspect := append(append([]string{}, checker.Docker[1:]...), "image", "inspect", image, "-f", "{{.Id}}")
		if err := exec.CommandContext(ctx, checker.Docker[0], inspect...).Run(); err != nil {
			remedy := "`docker pull " + image + "` first; validation and startup will both try to fetch it otherwise"
			// A registry that turns out to need credentials reports the
			// repository as nonexistent rather than unauthorised, so the
			// remedy names login as the second thing to try.
			if registry, _, found := strings.Cut(image, "/"); found && strings.ContainsAny(registry, ".:") {
				remedy = "`docker pull " + image + "`; if that reports the repository as nonexistent, the registry wants credentials — `docker login " + registry + "` first"
			}
			checks = append(checks, Check{
				Name:     "sing-box image",
				Severity: Warn,
				Detail:   image + " is not present locally",
				Remedy:   remedy,
			})
		} else {
			checks = append(checks, Check{Name: "sing-box image", Severity: Pass, Detail: image + " present"})
		}
	}
	return checks
}

// checkSelftestPrerequisites covers what only the self-test needs: a kernel
// WireGuard interface for its client side.
func checkSelftestPrerequisites() Check {
	if hostinfo.ModuleAvailable("wireguard") {
		return Check{Name: "wireguard module", Severity: Pass, Detail: "available"}
	}
	return Check{
		Name:     "wireguard module",
		Severity: Fail,
		Detail:   "the wireguard kernel module is neither loaded nor loadable",
		Remedy:   "the self-test's client is a kernel WireGuard interface; install the module or run the test from another host. The server itself does not need it — its endpoints run on the fork's userspace stack",
	}
}

func isIPv6Unspecified(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6() && addr.IsUnspecified()
}
