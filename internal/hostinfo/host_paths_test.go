package hostinfo

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolate points every probed path at an empty directory and the command
// search path at another one, so a test sees only what it puts there.
func isolate(t *testing.T) (root, bin string) {
	t.Helper()
	root, bin = t.TempDir(), t.TempDir()
	old := hostPaths
	t.Cleanup(func() { hostPaths = old })
	hostPaths.OVZMarkers = []string{filepath.Join(root, "vz"), filepath.Join(root, "beancounters")}
	hostPaths.Environ = filepath.Join(root, "environ")
	hostPaths.DockerEnv = filepath.Join(root, "dockerenv")
	hostPaths.Hypervisor = filepath.Join(root, "hypervisor")
	hostPaths.OSRelease = filepath.Join(root, "osrelease")
	hostPaths.ProcConfig = filepath.Join(root, "config.gz")
	hostPaths.BootConfigFmt = filepath.Join(root, "boot-config-%s")
	hostPaths.ModulesConfigFmt = filepath.Join(root, "modules-%s-config")
	hostPaths.MountInfo = filepath.Join(root, "mountinfo")
	hostPaths.BTF = filepath.Join(root, "btf")
	hostPaths.SysModule = filepath.Join(root, "sys-module") + "/"
	hostPaths.ProcSys = filepath.Join(root, "sys") + "/"
	t.Setenv("PATH", bin)
	return root, bin
}

func script(t *testing.T, bin, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectVirtualizationPrefersSystemd(t *testing.T) {
	_, bin := isolate(t)
	script(t, bin, "systemd-detect-virt", "echo kvm")
	got := DetectVirtualization()
	if got.Kind != "kvm" || got.Container || got.Source != "systemd-detect-virt" {
		t.Errorf("kvm = %+v", got)
	}
	script(t, bin, "systemd-detect-virt", "echo lxc")
	if got := DetectVirtualization(); got.Kind != "lxc" || !got.Container {
		t.Errorf("lxc = %+v", got)
	}
	// "none" is systemd's way of saying bare metal, with exit status 1.
	script(t, bin, "systemd-detect-virt", "echo none; exit 1")
	if got := DetectVirtualization(); got.Kind != "none" || got.Container {
		t.Errorf("none = %+v", got)
	}
}

func TestDetectVirtualizationFallsBackToMarkers(t *testing.T) {
	root, bin := isolate(t)
	if got := DetectVirtualization(); got.Kind != "unknown" || got.Container || got.Source != "no marker found" {
		t.Errorf("nothing = %+v", got)
	}

	// A systemd that says nothing is not an answer.
	script(t, bin, "systemd-detect-virt", "exit 1")
	if got := DetectVirtualization(); got.Kind != "unknown" {
		t.Errorf("silent systemd = %+v", got)
	}

	write(t, hostPaths.Hypervisor, "xen\n")
	if got := DetectVirtualization(); got.Kind != "xen" || got.Container || got.Source != hostPaths.Hypervisor {
		t.Errorf("hypervisor = %+v", got)
	}

	write(t, hostPaths.DockerEnv, "")
	if got := DetectVirtualization(); got.Kind != "docker" || !got.Container {
		t.Errorf("dockerenv = %+v", got)
	}

	write(t, hostPaths.Environ, "PATH=/bin\x00container=podman\x00HOME=/root\x00")
	if got := DetectVirtualization(); got.Kind != "podman" || !got.Container || got.Source != hostPaths.Environ {
		t.Errorf("environ = %+v", got)
	}
	// An empty value is not a container.
	write(t, hostPaths.Environ, "container=\x00")
	if got := DetectVirtualization(); got.Kind != "docker" {
		t.Errorf("empty container= should fall through: %+v", got)
	}

	write(t, filepath.Join(root, "beancounters"), "")
	if got := DetectVirtualization(); got.Kind != "openvz" || !got.Container || got.Source != hostPaths.OVZMarkers[1] {
		t.Errorf("openvz = %+v", got)
	}
}

func gz(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := gzip.NewWriter(f)
	w.Write([]byte(body))
	w.Close()
	f.Close()
}

func TestReadKernelConfigTriesEachPlaceInOrder(t *testing.T) {
	root, _ := isolate(t)
	if _, err := ReadKernelConfig(); err == nil || !strings.Contains(err.Error(), "kernel release") {
		t.Errorf("no osrelease: %v", err)
	}
	write(t, hostPaths.OSRelease, "7.0.0-test\n")

	cfg, err := ReadKernelConfig()
	if err != nil || cfg.Available || !strings.Contains(cfg.Source, "not found in") {
		t.Fatalf("nothing: %+v, %v", cfg, err)
	}
	if cfg.Enabled("CONFIG_BPF_SYSCALL") {
		t.Error("an unavailable config enabled something")
	}

	write(t, filepath.Join(root, "modules-7.0.0-test-config"), "CONFIG_BPF_SYSCALL=m\n")
	cfg, _ = ReadKernelConfig()
	if !cfg.Available || !strings.HasSuffix(cfg.Source, "modules-7.0.0-test-config") || !cfg.Enabled("CONFIG_BPF_SYSCALL") {
		t.Errorf("modules = %+v", cfg)
	}

	write(t, filepath.Join(root, "boot-config-7.0.0-test"), "CONFIG_BPF_SYSCALL=y\nCONFIG_BPF_JIT=y\n")
	cfg, _ = ReadKernelConfig()
	if !strings.HasSuffix(cfg.Source, "boot-config-7.0.0-test") || !cfg.Enabled("CONFIG_BPF_JIT") {
		t.Errorf("boot = %+v", cfg)
	}

	// A broken /proc/config.gz is skipped, not fatal.
	write(t, hostPaths.ProcConfig, "this is not gzip")
	cfg, _ = ReadKernelConfig()
	if !strings.HasSuffix(cfg.Source, "boot-config-7.0.0-test") {
		t.Errorf("a corrupt gz stopped the search: %+v", cfg)
	}

	gz(t, hostPaths.ProcConfig, "CONFIG_BPF_SYSCALL=y\nCONFIG_DEBUG_INFO_BTF=y\n")
	cfg, _ = ReadKernelConfig()
	if cfg.Source != hostPaths.ProcConfig || !cfg.Enabled("CONFIG_DEBUG_INFO_BTF") || cfg.Enabled("CONFIG_BPF_JIT") {
		t.Errorf("proc = %+v", cfg)
	}
}

func TestBPFFilesystemMounted(t *testing.T) {
	root, _ := isolate(t)
	if BPFFilesystemMounted() {
		t.Error("no mountinfo reported as mounted")
	}
	write(t, hostPaths.MountInfo, "25 1 0:22 / /sys rw - sysfs sysfs rw\n30 25 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")
	if BPFFilesystemMounted() {
		t.Error("a host without bpffs reported it")
	}
	write(t, hostPaths.MountInfo, "40 25 0:30 / /sys/fs/bpf rw,nosuid - bpf bpf rw,mode=700\n")
	if !BPFFilesystemMounted() {
		t.Error("bpffs not noticed")
	}
	// The type can also end a line.
	write(t, hostPaths.MountInfo, "40 25 0:30 / /sys/fs/bpf rw - bpf")
	if !BPFFilesystemMounted() {
		t.Error("bpffs at end of line not noticed")
	}
	_ = root
}

func TestBTFAndModuleProbes(t *testing.T) {
	root, bin := isolate(t)
	if BTFAvailable() {
		t.Error("BTF reported without the file")
	}
	write(t, hostPaths.BTF, "")
	if !BTFAvailable() {
		t.Error("BTF not noticed")
	}

	if ModuleAvailable("xdp_thing") {
		t.Error("a module that is nowhere was reported")
	}
	if err := os.MkdirAll(filepath.Join(root, "sys-module", "loaded_mod"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !ModuleAvailable("loaded_mod") {
		t.Error("a loaded module was not noticed")
	}
	// Present but not loaded: modinfo is the only witness.
	script(t, bin, "modinfo", `[ "$1" = unloaded_mod ]`)
	if !ModuleAvailable("unloaded_mod") {
		t.Error("an available module was not noticed through modinfo")
	}
	if ModuleAvailable("absent_mod") {
		t.Error("modinfo's refusal was ignored")
	}
}

func TestSysctlThroughAFixtureRoot(t *testing.T) {
	root, _ := isolate(t)
	write(t, filepath.Join(root, "sys", "net", "ipv4", "ip_forward"), "1\n")
	got, err := Sysctl("net.ipv4.ip_forward")
	if err != nil || got != "1" {
		t.Errorf("Sysctl = %q, %v", got, err)
	}
}

func TestReadPortsSkipsMissingFilesButNotBrokenOnes(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "udp")
	write(t, good, "  sl  local_address rem_address   st\n   0: 00000000:1F90 00000000:0000 07 x\n")
	ports, err := readPorts([]string{filepath.Join(dir, "absent6"), good}, "")
	if err != nil || !ports[8080] {
		t.Errorf("ports = %v, %v", ports, err)
	}
	empty := filepath.Join(dir, "empty")
	write(t, empty, "")
	if _, err := readPorts([]string{empty}, ""); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty file: %v", err)
	}
}

func TestLiveWrappersWorkOnThisHost(t *testing.T) {
	// The real files, only for their shape: whatever the machine is, these must
	// not fail on a Linux host.
	if _, err := os.Stat("/proc/net/udp"); err != nil {
		t.Skip("no /proc/net")
	}
	if _, err := ListeningUDPPorts(); err != nil {
		t.Errorf("UDP: %v", err)
	}
	if _, err := ListeningTCPPorts(); err != nil {
		t.Errorf("TCP: %v", err)
	}
	if _, known := LogrotateCovers("/var/log/definitely-not-a-real-file.log"); !known {
		t.Log("logrotate.d is unreadable here; the wrapper reported unknown")
	}
	if iface, err := DefaultRouteInterface(); err == nil && iface == "" {
		t.Error("a route without an interface name")
	}
}
