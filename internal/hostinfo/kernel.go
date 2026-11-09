package hostinfo

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// hostPaths are the files these probes read, in one place so a test can point
// them at a fixture instead of at whatever machine it runs on.
var hostPaths = struct {
	OVZMarkers                                             []string
	Environ, DockerEnv, Hypervisor                         string
	OSRelease, ProcConfig, BootConfigFmt, ModulesConfigFmt string
	MountInfo, BTF, SysModule, ProcSys                     string
}{
	OVZMarkers:       []string{"/proc/vz", "/proc/user_beancounters"},
	Environ:          "/proc/1/environ",
	DockerEnv:        "/.dockerenv",
	Hypervisor:       "/sys/hypervisor/type",
	OSRelease:        "/proc/sys/kernel/osrelease",
	ProcConfig:       "/proc/config.gz",
	BootConfigFmt:    "/boot/config-%s",
	ModulesConfigFmt: "/lib/modules/%s/config",
	MountInfo:        "/proc/self/mountinfo",
	BTF:              "/sys/kernel/btf/vmlinux",
	SysModule:        "/sys/module/",
	ProcSys:          "/proc/sys/",
}

// Virtualization describes how the host is virtualised, to the extent that can
// be told. The distinction that matters is container versus machine: an
// OpenVZ or LXC guest shares the host kernel and cannot load an XDP program,
// however complete its /proc looks.
type Virtualization struct {
	// Kind is systemd's vocabulary where available ("none", "kvm", "lxc",
	// "openvz", "docker", …), or "unknown".
	Kind string
	// Container is true when the kernel is shared with a host, which is what
	// rules out XDP.
	Container bool
	// Source names how this was determined, because the answer is a guess
	// often enough that its provenance belongs in the report.
	Source string
}

// DetectVirtualization identifies the virtualisation in use.
func DetectVirtualization() Virtualization {
	// systemd-detect-virt is the most reliable answer when present. Exit code
	// 1 means "none", which is not a failure.
	if path, err := exec.LookPath("systemd-detect-virt"); err == nil {
		out, _ := exec.Command(path).Output()
		kind := strings.TrimSpace(string(out))
		if kind != "" {
			return Virtualization{
				Kind:      kind,
				Container: isContainerKind(kind),
				Source:    "systemd-detect-virt",
			}
		}
	}

	// OpenVZ leaves these behind and nothing else does.
	for _, marker := range hostPaths.OVZMarkers {
		if _, err := os.Stat(marker); err == nil {
			return Virtualization{Kind: "openvz", Container: true, Source: marker}
		}
	}
	if data, err := os.ReadFile(hostPaths.Environ); err == nil {
		for _, entry := range strings.Split(string(data), "\x00") {
			if value, ok := strings.CutPrefix(entry, "container="); ok && value != "" {
				return Virtualization{Kind: value, Container: true, Source: hostPaths.Environ}
			}
		}
	}
	if _, err := os.Stat(hostPaths.DockerEnv); err == nil {
		return Virtualization{Kind: "docker", Container: true, Source: hostPaths.DockerEnv}
	}
	if data, err := os.ReadFile(hostPaths.Hypervisor); err == nil {
		return Virtualization{Kind: strings.TrimSpace(string(data)), Source: hostPaths.Hypervisor}
	}
	return Virtualization{Kind: "unknown", Source: "no marker found"}
}

func isContainerKind(kind string) bool {
	switch kind {
	case "openvz", "lxc", "lxc-libvirt", "docker", "podman", "systemd-nspawn", "rkt", "wsl", "proot", "pouch":
		return true
	}
	return false
}

// KernelConfig is the subset of the running kernel's build options that
// decides whether the XDP blocker can work.
type KernelConfig struct {
	// Available is false when the config could not be read at all, in which
	// case the other fields mean nothing and the caller must say "unknown"
	// rather than "no".
	Available bool
	Source    string
	Options   map[string]string
}

// kernelConfigOptions are the ones worth reading. BPF_SYSCALL is the hard
// requirement; the others explain *how well* it will work rather than whether.
var kernelConfigOptions = []string{
	"CONFIG_BPF_SYSCALL",
	"CONFIG_BPF_JIT",
	"CONFIG_XDP_SOCKETS",
	"CONFIG_DEBUG_INFO_BTF",
}

// ReadKernelConfig reads the running kernel's configuration from wherever the
// distribution put it.
func ReadKernelConfig() (*KernelConfig, error) {
	release, err := os.ReadFile(hostPaths.OSRelease)
	if err != nil {
		return nil, fmt.Errorf("read kernel release: %w", err)
	}
	version := strings.TrimSpace(string(release))

	candidates := []string{
		hostPaths.ProcConfig,
		fmt.Sprintf(hostPaths.BootConfigFmt, version),
		fmt.Sprintf(hostPaths.ModulesConfigFmt, version),
	}
	for _, path := range candidates {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		var reader io.Reader = file
		if strings.HasSuffix(path, ".gz") {
			gz, err := gzip.NewReader(file)
			if err != nil {
				continue
			}
			defer gz.Close()
			reader = gz
		}
		options, err := parseKernelConfig(reader)
		if err != nil {
			continue
		}
		return &KernelConfig{Available: true, Source: path, Options: options}, nil
	}
	return &KernelConfig{Available: false, Source: "not found in " + strings.Join(candidates, ", ")}, nil
}

// Enabled reports whether an option is built in or as a module.
func (c *KernelConfig) Enabled(option string) bool {
	switch c.Options[option] {
	case "y", "m":
		return true
	}
	return false
}

func parseKernelConfig(reader io.Reader) (map[string]string, error) {
	wanted := make(map[string]struct{}, len(kernelConfigOptions))
	for _, name := range kernelConfigOptions {
		wanted[name] = struct{}{}
	}

	options := map[string]string{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if _, want := wanted[name]; !want {
			continue
		}
		options[name] = strings.Trim(value, `"`)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return options, nil
}

// BPFFilesystemMounted reports whether bpffs is mounted, which pinned maps and
// programs need.
func BPFFilesystemMounted() bool {
	data, err := os.ReadFile(hostPaths.MountInfo)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.Contains(line, " bpf ") || strings.HasSuffix(line, " bpf") {
			return true
		}
	}
	return false
}

// BTFAvailable reports whether the kernel exposes its own BTF, which CO-RE
// relocations in a modern eBPF object need.
func BTFAvailable() bool {
	_, err := os.Stat(hostPaths.BTF)
	return err == nil
}

// ModuleAvailable reports whether a kernel module is loaded or loadable.
func ModuleAvailable(name string) bool {
	if _, err := os.Stat(hostPaths.SysModule + name); err == nil {
		return true
	}
	// Built-in modules have no /sys/module entry on every kernel, and an
	// unloaded-but-present module has none either; modinfo covers both.
	if path, err := exec.LookPath("modinfo"); err == nil {
		if err := exec.Command(path, name).Run(); err == nil {
			return true
		}
	}
	return false
}

// Sysctl reads a single sysctl through /proc/sys.
func Sysctl(name string) (string, error) {
	path := hostPaths.ProcSys + strings.ReplaceAll(name, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
