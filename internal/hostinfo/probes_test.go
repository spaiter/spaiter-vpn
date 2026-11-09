package hostinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsContainerKind(t *testing.T) {
	// A container shares the host kernel, which is what rules out XDP; a
	// machine, even a virtual one, loads its own.
	for kind, want := range map[string]bool{
		"openvz": true, "lxc": true, "lxc-libvirt": true, "docker": true, "podman": true,
		"systemd-nspawn": true, "wsl": true, "proot": true,
		"kvm": false, "qemu": false, "vmware": false, "xen": false, "microsoft": false,
		"none": false, "unknown": false, "": false, "Docker": false,
	} {
		if got := isContainerKind(kind); got != want {
			t.Errorf("isContainerKind(%q) = %v, want %v", kind, got, want)
		}
	}
}

const kernelConfig = `#
# Automatically generated file; DO NOT EDIT.
#
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
# CONFIG_XDP_SOCKETS is not set
CONFIG_DEBUG_INFO_BTF=m
CONFIG_LOCALVERSION="-custom"
CONFIG_BPF_JIT_ALWAYS_ON=y
no equals sign here
`

func TestParseKernelConfigKeepsOnlyTheOptionsThatMatter(t *testing.T) {
	options, err := parseKernelConfig(strings.NewReader(kernelConfig))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"CONFIG_BPF_SYSCALL":    "y",
		"CONFIG_BPF_JIT":        "y",
		"CONFIG_DEBUG_INFO_BTF": "m",
	}
	if len(options) != len(want) {
		t.Fatalf("options = %v, want %v (a prefix match on BPF_JIT_ALWAYS_ON or a comment must not leak in)", options, want)
	}
	for name, value := range want {
		if options[name] != value {
			t.Errorf("%s = %q, want %q", name, options[name], value)
		}
	}
}

func TestParseKernelConfigStripsQuotes(t *testing.T) {
	// None of the wanted options is a string today; the quoting rule must still
	// hold if one is added.
	options, err := parseKernelConfig(strings.NewReader("CONFIG_BPF_SYSCALL=\"y\"\n"))
	if err != nil || options["CONFIG_BPF_SYSCALL"] != "y" {
		t.Fatalf("options=%v err=%v", options, err)
	}
}

func TestParseKernelConfigToleratesVeryLongLines(t *testing.T) {
	long := "CONFIG_CMDLINE=\"" + strings.Repeat("x", 200_000) + "\"\nCONFIG_BPF_SYSCALL=y\n"
	options, err := parseKernelConfig(strings.NewReader(long))
	if err != nil {
		t.Fatalf("a long line aborted the parse: %v", err)
	}
	if options["CONFIG_BPF_SYSCALL"] != "y" {
		t.Fatalf("options after the long line were lost: %v", options)
	}
}

func TestParseKernelConfigReportsAnOversizedLine(t *testing.T) {
	huge := "CONFIG_X=" + strings.Repeat("x", 2*1024*1024) + "\n"
	if _, err := parseKernelConfig(strings.NewReader(huge)); err == nil {
		t.Fatal("a line over the scanner limit must be an error, not a silently empty result")
	}
}

func TestKernelConfigEnabled(t *testing.T) {
	c := &KernelConfig{Available: true, Options: map[string]string{
		"CONFIG_BPF_SYSCALL": "y", "CONFIG_DEBUG_INFO_BTF": "m", "CONFIG_BPF_JIT": "n", "CONFIG_XDP_SOCKETS": "",
	}}
	for option, want := range map[string]bool{
		"CONFIG_BPF_SYSCALL": true, "CONFIG_DEBUG_INFO_BTF": true, // built in or as a module
		"CONFIG_BPF_JIT": false, "CONFIG_XDP_SOCKETS": false, "CONFIG_NOT_THERE": false,
	} {
		if got := c.Enabled(option); got != want {
			t.Errorf("Enabled(%s) = %v, want %v", option, got, want)
		}
	}
}

const procNetRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0100A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0100000A	0003	0	0	100	00000000	0	0	0
eth0	0000000A	00000000	0001	0	0	100	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

func TestDefaultRouteInterfacePicksTheCheapestDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(procNetRoute), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := defaultRouteInterface(path)
	if err != nil {
		t.Fatal(err)
	}
	// wlan0 is listed first but costs 600; the kernel uses eth0 at 100. docker0
	// has metric 0 but is not a default route.
	if got != "eth0" {
		t.Fatalf("interface = %q, want eth0", got)
	}
}

func TestDefaultRouteInterfaceFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	header := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
	for name, tc := range map[string]struct{ path, want string }{
		"missing":     {filepath.Join(dir, "nope"), "open"},
		"empty":       {write("empty", ""), "is empty"},
		"no default":  {write("nodefault", header+"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"), "no IPv4 default route"},
		"garbled":     {write("garbled", header+"eth0\t00000000\t0100000A\t0003\t0\t0\tNaN\t00000000\t0\t0\t0\nshort\n"), "no IPv4 default route"},
		"header only": {write("header", header), "no IPv4 default route"},
	} {
		t.Run(name, func(t *testing.T) {
			iface, err := defaultRouteInterface(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got (%q, %v), want an error containing %q", iface, err, tc.want)
			}
		})
	}
}

func TestLogrotateCoversFindsThePathOrItsLogGlob(t *testing.T) {
	dir := t.TempDir()
	put := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	put("unrelated", "/var/log/nginx/*.log {\n  daily\n}\n")
	put("exact", "/var/log/spaiter-vpn/core.log {\n  weekly\n}\n")
	put("glob", "/srv/app/logs/*.log {\n  weekly\n}\n")

	covers, known := logrotateCovers(dir, "/var/log/spaiter-vpn/core.log")
	if !covers || !known {
		t.Fatalf("the exact path is named in a stanza: covers=%v known=%v", covers, known)
	}
	covers, known = logrotateCovers(dir, "/srv/app/logs/app.log")
	if !covers || !known {
		t.Fatalf("a directory glob names the file: covers=%v known=%v", covers, known)
	}
	covers, known = logrotateCovers(dir, "/var/log/other/thing.log")
	if covers || !known {
		t.Fatalf("nothing mentions it: covers=%v known=%v (must be a definite no)", covers, known)
	}
}

func TestLogrotateCoversAdmitsWhenItCannotTell(t *testing.T) {
	covers, known := logrotateCovers(filepath.Join(t.TempDir(), "absent"), "/var/log/x.log")
	if covers || known {
		t.Fatalf("an unreadable directory must be reported as unknown, not as not-rotated: covers=%v known=%v", covers, known)
	}
}

func TestSysctlReadsThroughProcSys(t *testing.T) {
	if _, err := os.Stat("/proc/sys/kernel/osrelease"); err != nil {
		t.Skip("no /proc/sys on this platform")
	}
	got, err := Sysctl("kernel.osrelease")
	if err != nil || got == "" || strings.ContainsAny(got, "\n ") {
		t.Fatalf("Sysctl(kernel.osrelease) = %q, %v: want one trimmed word", got, err)
	}
	if _, err := Sysctl("kernel.no_such_knob"); err == nil || !strings.Contains(err.Error(), "/proc/sys/kernel/no_such_knob") {
		t.Fatalf("a missing sysctl must name the path it tried: %v", err)
	}
}
