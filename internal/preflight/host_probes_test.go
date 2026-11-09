package preflight

import (
	"errors"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/hostinfo"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// presentHost replaces every host probe for one test and restores them after.
type presentHost struct {
	virt     hostinfo.Virtualization
	config   hostinfo.KernelConfig
	configEr error
	btf      bool
	bpffs    bool
	tcp, udp map[uint16]bool
	portsErr error
	uid      int
	module   bool
}

func (h presentHost) install(t *testing.T) {
	t.Helper()
	oldVirt, oldConfig, oldBTF, oldBPF := detectVirtualization, readKernelConfig, btfAvailable, bpfMounted
	oldTCP, oldUDP, oldUID, oldModule := listeningTCPPorts, listeningUDPPorts, effectiveUID, moduleAvailable
	detectVirtualization = func() hostinfo.Virtualization { return h.virt }
	readKernelConfig = func() (*hostinfo.KernelConfig, error) {
		config := h.config
		return &config, h.configEr
	}
	btfAvailable = func() bool { return h.btf }
	bpfMounted = func() bool { return h.bpffs }
	listeningTCPPorts = func() (map[uint16]bool, error) { return h.tcp, h.portsErr }
	listeningUDPPorts = func() (map[uint16]bool, error) { return h.udp, nil }
	effectiveUID = func() int { return h.uid }
	moduleAvailable = func(string) bool { return h.module }
	t.Cleanup(func() {
		detectVirtualization, readKernelConfig, btfAvailable, bpfMounted = oldVirt, oldConfig, oldBTF, oldBPF
		listeningTCPPorts, listeningUDPPorts, effectiveUID, moduleAvailable = oldTCP, oldUDP, oldUID, oldModule
	})
}

func kernelWith(options ...string) hostinfo.KernelConfig {
	config := hostinfo.KernelConfig{Available: true, Source: "/boot/config", Options: map[string]string{}}
	for _, option := range options {
		config.Options[option] = "y"
	}
	return config
}

func xdpSpec() profile.Spec {
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = []string{"lo"}
	return spec
}

func TestXDPChecksFollowWhatTheKernelOffers(t *testing.T) {
	good := presentHost{
		virt:   hostinfo.Virtualization{Kind: "kvm", Source: "systemd-detect-virt"},
		config: kernelWith("CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT", "CONFIG_XDP_SOCKETS"),
		btf:    true, bpffs: true,
	}
	cases := map[string]struct {
		mutate   func(*presentHost)
		name     string
		severity Severity
		contains string
	}{
		"everything present":       {func(*presentHost) {}, "xdp bpf support", Pass, "all enabled"},
		"a container":              {func(h *presentHost) { h.virt = hostinfo.Virtualization{Kind: "lxc", Container: true, Source: "cgroup"} }, "xdp kernel", Fail, "lxc container"},
		"virtualisation unknown":   {func(h *presentHost) { h.virt = hostinfo.Virtualization{Kind: "unknown", Source: "none"} }, "xdp kernel", Unknown, "could not determine"},
		"kernel config unreadable": {func(h *presentHost) { h.config = hostinfo.KernelConfig{} }, "xdp bpf support", Unknown, "not readable"},
		"kernel config errors":     {func(h *presentHost) { h.configEr = errors.New("no") }, "xdp bpf support", Unknown, "not readable"},
		"no bpf syscall":           {func(h *presentHost) { h.config = kernelWith("CONFIG_BPF_JIT") }, "xdp bpf support", Fail, "CONFIG_BPF_SYSCALL is not enabled"},
		"no jit or xdp sockets":    {func(h *presentHost) { h.config = kernelWith("CONFIG_BPF_SYSCALL") }, "xdp bpf support", Warn, "CONFIG_BPF_JIT, CONFIG_XDP_SOCKETS missing"},
		"no btf":                   {func(h *presentHost) { h.btf = false }, "xdp btf", Warn, "absent"},
		"no bpffs":                 {func(h *presentHost) { h.bpffs = false }, "bpffs", Warn, "no bpf filesystem"},
	}
	for label, tc := range cases {
		host := good
		tc.mutate(&host)
		host.install(t)
		got := find(checkXDP(xdpSpec()), tc.name)
		if got == nil || got.Severity != tc.severity || !strings.Contains(got.Detail, tc.contains) {
			t.Errorf("%s: %+v", label, got)
		}
		if got != nil && got.Severity != Pass && got.Remedy == "" {
			t.Errorf("%s: no way forward", label)
		}
	}
}

func TestPortCheckAdmitsWhenItCannotReadTheBoundPorts(t *testing.T) {
	presentHost{portsErr: errors.New("no /proc"), uid: 1000}.install(t)
	got := checkPorts(profile.Defaults([]string{"alice"}), false)
	if len(got) != 1 || got[0].Severity != Unknown || !strings.Contains(got[0].Detail, "cannot read the bound ports") {
		t.Errorf("ports: %+v", got)
	}
	if c := checkManagementPort(profile.Defaults([]string{"alice"}), false); c.Severity != Unknown && c.Severity != Warn {
		t.Errorf("management: %+v", c)
	}
}

func TestManagementPortListenerIsReadStrictly(t *testing.T) {
	presentHost{tcp: map[uint16]bool{}, uid: 1000}.install(t)
	spec := profile.Defaults([]string{"alice"})
	for listen, want := range map[string]Severity{
		"":             Warn,
		"nonsense":     Unknown,
		":not-a-port":  Unknown,
		":9090":        Pass,
		"127.0.0.1:99": Pass,
	} {
		spec.ClashAPIListen = listen
		if got := checkManagementPort(spec, false); got.Severity != want {
			t.Errorf("%q: %+v", listen, got)
		}
	}
	presentHost{portsErr: errors.New("no /proc"), uid: 1000}.install(t)
	spec.ClashAPIListen = ":9090"
	if got := checkManagementPort(spec, false); got.Severity != Unknown || !strings.Contains(got.Remedy, "9090") {
		t.Errorf("unreadable: %+v", got)
	}
}

func TestPrivilegesAndTheSelfTestModule(t *testing.T) {
	presentHost{uid: 0, module: false}.install(t)
	if got := checkPrivileges(); got.Severity != Pass || !strings.Contains(got.Detail, "root") {
		t.Errorf("root: %+v", got)
	}
	if got := checkSelftestPrerequisites(); got.Severity != Fail || got.Remedy == "" {
		t.Errorf("no wireguard module: %+v", got)
	}
	presentHost{uid: 1000, module: true}.install(t)
	if got := checkSelftestPrerequisites(); got.Severity != Pass {
		t.Errorf("module present: %+v", got)
	}
}
