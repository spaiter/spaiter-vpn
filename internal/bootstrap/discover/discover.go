package discover

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/hostinfo"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

type Runner interface {
	LookPath(name string) (string, error)
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type systemRunner struct{}

func (systemRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (systemRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type Options struct {
	Layout        Layout
	OSReleasePath string
	SystemdPath   string
	GOOS          string
	GOARCH        string
	EUID          func() int
	Runner        Runner
	DefaultRoute  func() (string, error)
	FirewallProbe func([]firewall.Rule) Firewall
	// AptRoot prefixes the apt configuration paths, for tests.
	AptRoot string
}

func DefaultOptions() Options {
	return Options{
		Layout:        DefaultLayout(),
		OSReleasePath: "/etc/os-release",
		SystemdPath:   "/run/systemd/system",
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		EUID:          os.Geteuid,
		Runner:        systemRunner{},
		DefaultRoute:  hostinfo.DefaultRouteInterface,
		FirewallProbe: probeFirewall,
	}
}

// Run inspects the host without writing, pulling images, refreshing package
// metadata or generating credentials.
func Run(ctx context.Context, desired state.State, options Options) (Observed, error) {
	if err := desired.Validate(); err != nil {
		return Observed{}, fmt.Errorf("desired state: %w", err)
	}
	options = fillOptions(options)

	observed := Observed{
		APIVersion:       ObservationVersion,
		Privileges:       Privileges{EUID: options.EUID()},
		Credentials:      map[state.SecretRef]File{},
		CertificateFiles: map[string]File{},
	}
	observed.Platform = discoverPlatform(options)
	observed.Docker = discoverDocker(ctx, options.Runner)
	if desired.Bootstrap.InstallDocker && (!observed.Docker.CLIAvailable || !observed.Docker.ComposeAvailable) {
		observed.Docker.Install = discoverDockerInstall(ctx, options)
	}
	observed.Network = discoverNetwork(options.DefaultRoute)

	resolvedXDP := desired.Deployment.XDPInterfaces
	if len(resolvedXDP) == 1 && resolvedXDP[0] == "auto" {
		resolvedXDP = nil
		if observed.Network.DefaultInterface != "" {
			resolvedXDP = []string{observed.Network.DefaultInterface}
		}
	}
	spec, err := desired.PreflightSpec(resolvedXDP)
	if err != nil {
		return Observed{}, err
	}
	observed.Firewall = options.FirewallProbe(FirewallRules(desired, spec))

	observed.ExistingDesired = inspectDesired(options.Layout.DesiredPath())
	receipt, recreatePending := inspectReceiptState(options.Layout.CurrentReceiptPath())
	observed.Runtime = Runtime{
		Config:          inspectFile(options.Layout.ConfigPath()),
		Secrets:         inspectFile(options.Layout.SecretsPath()),
		Compose:         inspectFile(options.Layout.ComposePath()),
		Receipt:         receipt,
		RecreatePending: recreatePending,
	}
	observed.Logrotate = inspectFile(options.Layout.LogrotatePath)
	if desired.Bot.Enabled && desired.Bot.DedicatedUser {
		account := LookupSystemUser(deploy.BotUserName)
		observed.BotUser = &account
	}
	if desired.Bootstrap.ManageControl {
		file := inspectFile(options.Layout.ControlUnitPath)
		observed.ControlUnit = &file
	}
	for _, reference := range credentialRefs(desired) {
		observed.Credentials[reference] = inspectCredential(options.Layout.CredentialDir(), reference)
	}
	for _, path := range certificatePaths(desired) {
		observed.CertificateFiles[path] = inspectFile(path)
	}
	return observed, nil
}

func fillOptions(options Options) Options {
	defaults := DefaultOptions()
	if options.Layout.ConfigRoot == "" {
		options.Layout.ConfigRoot = defaults.Layout.ConfigRoot
	}
	if options.Layout.DataRoot == "" {
		options.Layout.DataRoot = defaults.Layout.DataRoot
	}
	if options.Layout.LogrotatePath == "" {
		options.Layout.LogrotatePath = defaults.Layout.LogrotatePath
	}
	if options.Layout.ControlUnitPath == "" {
		options.Layout.ControlUnitPath = defaults.Layout.ControlUnitPath
	}
	if options.OSReleasePath == "" {
		options.OSReleasePath = defaults.OSReleasePath
	}
	if options.SystemdPath == "" {
		options.SystemdPath = defaults.SystemdPath
	}
	if options.GOOS == "" {
		options.GOOS = defaults.GOOS
	}
	if options.GOARCH == "" {
		options.GOARCH = defaults.GOARCH
	}
	if options.EUID == nil {
		options.EUID = defaults.EUID
	}
	if options.Runner == nil {
		options.Runner = defaults.Runner
	}
	if options.DefaultRoute == nil {
		options.DefaultRoute = defaults.DefaultRoute
	}
	if options.FirewallProbe == nil {
		options.FirewallProbe = defaults.FirewallProbe
	}
	return options
}

func discoverPlatform(options Options) Platform {
	platform := Platform{OS: options.GOOS, Arch: options.GOARCH}
	if values, err := readOSRelease(options.OSReleasePath); err == nil {
		platform.ID = values["ID"]
		platform.VersionID = values["VERSION_ID"]
	}
	if info, err := os.Stat(options.SystemdPath); err == nil && info.IsDir() {
		platform.Systemd = true
	}
	return platform
}

func readOSRelease(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		values[key] = value
	}
	return values, scanner.Err()
}

func discoverDocker(ctx context.Context, runner Runner) Docker {
	dockerPath, err := runner.LookPath("docker")
	if err != nil {
		return Docker{}
	}
	result := Docker{CLIAvailable: true}
	candidates := []struct {
		name string
		args []string
		sudo bool
	}{{dockerPath, []string{"version", "--format", "{{.Server.Version}}"}, false}}
	if sudoPath, err := runner.LookPath("sudo"); err == nil {
		candidates = append(candidates, struct {
			name string
			args []string
			sudo bool
		}{sudoPath, []string{"-n", dockerPath, "version", "--format", "{{.Server.Version}}"}, true})
	}
	var command struct {
		name   string
		prefix []string
	}
	for _, candidate := range candidates {
		out, runErr := runner.Output(ctx, candidate.name, candidate.args...)
		if runErr != nil {
			result.Error = firstLine(string(out))
			if result.Error == "" {
				result.Error = runErr.Error()
			}
			continue
		}
		result.DaemonReachable = true
		result.ViaSudo = candidate.sudo
		result.ServerVersion = firstLine(string(out))
		command.name = candidate.name
		if candidate.sudo {
			command.prefix = []string{"-n", dockerPath}
		}
		break
	}
	if !result.DaemonReachable {
		return result
	}
	args := append(append([]string{}, command.prefix...), "compose", "version", "--short")
	if _, err := runner.Output(ctx, command.name, args...); err == nil {
		result.ComposeAvailable = true
	}
	return result
}

// discoverDockerInstall asks the installer's own precondition check, read-only,
// so the plan refuses exactly what the apply would.
func discoverDockerInstall(ctx context.Context, options Options) *DockerInstall {
	installer := dockerinstall.Installer{Runner: runnerAdapter{options.Runner}, Root: options.AptRoot}
	conflicts, foreign, err := installer.Preconditions(ctx)
	result := &DockerInstall{Conflicts: conflicts, ForeignSources: foreign}
	if result.Conflicts == nil {
		result.Conflicts = []string{}
	}
	if result.ForeignSources == nil {
		result.ForeignSources = []string{}
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

type runnerAdapter struct{ Runner }

func (r runnerAdapter) Run(ctx context.Context, _ []string, name string, args ...string) ([]byte, error) {
	return r.Output(ctx, name, args...)
}

func discoverNetwork(route func() (string, error)) Network {
	name, err := route()
	if err != nil {
		return Network{Error: err.Error()}
	}
	return Network{DefaultInterface: name}
}

func probeFirewall(rules []firewall.Rule) Firewall {
	backend := firewall.Detect()
	result := Firewall{Kind: string(backend.Kind), Active: backend.Active, Detail: backend.Detail, Required: []string{}, Rules: map[string]string{}}
	for _, rule := range rules {
		result.Required = append(result.Required, rule.String())
	}
	sort.Strings(result.Required)
	statuses, err := backend.Check(rules)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	result.Readable = true
	for _, rule := range rules {
		switch statuses[rule.String()] {
		case firewall.Allowed:
			result.Rules[rule.String()] = "allowed"
		case firewall.Blocked:
			result.Rules[rule.String()] = "blocked"
		default:
			result.Rules[rule.String()] = "unknown"
		}
	}
	return result
}

func inspectDesired(path string) ExistingDesired {
	file := inspectFile(path)
	if file.Status == FileAbsent {
		return ExistingDesired{Status: FileAbsent}
	}
	if file.Status != FileRegular {
		return ExistingDesired{Status: FileInvalid, Error: file.Error}
	}
	loaded, err := state.Load(path)
	if err != nil {
		return ExistingDesired{Status: FileInvalid, Error: err.Error()}
	}
	digest, err := loaded.Digest()
	if err != nil {
		return ExistingDesired{Status: FileInvalid, Error: err.Error()}
	}
	return ExistingDesired{Status: FileRegular, Digest: digest, State: &loaded}
}

func inspectFile(path string) File {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return File{Status: FileAbsent}
	}
	if err != nil {
		return File{Status: FileInvalid, Error: err.Error()}
	}
	result := File{Status: FileRegular, Mode: uint32(info.Mode().Perm()), Size: info.Size()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		result.UID = stat.Uid
	}
	if !info.Mode().IsRegular() {
		result.Status = FileInvalid
		result.Error = "not a regular file"
	}
	return result
}

// inspectReceipt reports a receipt as present only when it claims files.
//
// A receipt that owns no files is not a deployment. Recovery writes exactly
// that after an interrupted FIRST install, to record which firewall rules the
// killed apply had opened — without it those rules stay indistinguishable from
// the operator's forever. Counting it as runtime state made the planner refuse
// the retry as "an untracked deployment", so a crash during the first install
// left the host needing a manual `rm -rf` to become installable again. That is
// the opposite of what recording the ownership was for.
func inspectReceipt(path string) File {
	result, _ := inspectReceiptState(path)
	return result
}

func inspectReceiptState(path string) (File, bool) {
	result := inspectFile(path)
	if result.Status != FileRegular {
		return result, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return File{Status: FileInvalid, Error: err.Error()}, false
	}
	var receipt transaction.Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return File{Status: FileInvalid, Error: fmt.Sprintf("parse receipt: %v", err)}, false
	}
	if receipt.APIVersion != transaction.ReceiptAPIVersion || receipt.Files == nil {
		return File{Status: FileInvalid, Error: "receipt has an unsupported version or no files map"}, false
	}
	if len(receipt.Files) == 0 {
		if (len(receipt.Firewall) == 0 && !receipt.RecreatePending) || receipt.Sequence != 0 || receipt.Transaction != "" {
			return File{Status: FileInvalid, Error: "receipt claims no deployment files and is not a recovery-ownership receipt"}, false
		}
		return File{Status: FileAbsent}, receipt.RecreatePending
	}
	if receipt.Sequence == 0 || receipt.Transaction == "" {
		return File{Status: FileInvalid, Error: "deployment receipt has no transaction identity"}, false
	}
	return result, receipt.RecreatePending
}

func inspectCredential(dir string, reference state.SecretRef) File {
	result := inspectFile(filepath.Join(dir, string(reference)))
	if result.Status != FileRegular {
		return result
	}
	if result.UID != 0 {
		result.Status = FileInvalid
		result.Error = fmt.Sprintf("owned by uid %d, want root", result.UID)
		return result
	}
	if result.Mode&0o077 != 0 {
		result.Status = FileInvalid
		result.Error = fmt.Sprintf("mode %04o exposes the credential", result.Mode)
		return result
	}
	if result.Size == 0 {
		result.Status = FileInvalid
		result.Error = "credential file is empty"
	}
	return result
}

// CredentialRefs names every credential the desired state needs on disk.
func CredentialRefs(desired state.State) []state.SecretRef { return credentialRefs(desired) }

func credentialRefs(desired state.State) []state.SecretRef {
	set := map[state.SecretRef]bool{}
	if desired.Bot.Enabled {
		set[desired.Bot.TelegramToken] = true
	}
	if desired.DDNS != nil {
		set[desired.DDNS.Token] = true
	}
	if certs := desired.Deployment.Certificates; certs != nil && certs.ACMEDNS != nil {
		if certs.ACMEDNS.Cloudflare != nil {
			set[certs.ACMEDNS.Cloudflare.APIToken] = true
		}
		if certs.ACMEDNS.Account != nil {
			set[certs.ACMEDNS.Account.Password] = true
		}
	}
	refs := make([]state.SecretRef, 0, len(set))
	for ref := range set {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
	return refs
}

func certificatePaths(desired state.State) []string {
	certs := desired.Deployment.Certificates
	if certs == nil || certs.Files == nil {
		return nil
	}
	paths := []string{certs.Files.CertificatePath, certs.Files.KeyPath}
	sort.Strings(paths)
	return paths
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if line, _, found := strings.Cut(value, "\n"); found {
		return line
	}
	return value
}

// LookupSystemUser reports an account and its primary group.
func LookupSystemUser(name string) SystemUser {
	result := SystemUser{Name: name}
	account, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			result.Error = err.Error()
		}
		return result
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 {
		result.Error = fmt.Sprintf("account %s has uid %s gid %s, not an unprivileged numeric account", name, account.Uid, account.Gid)
		return result
	}
	result.Exists, result.UID, result.GID = true, uint32(uid), uint32(gid)
	return result
}

// FirewallRules is every rule the deployment needs open: the protocols' ports
// and, with the bot enabled, its subscription port. Clients poll that port
// directly, and a subscription they cannot reach keeps them on whatever they
// cached until it stops working.
func FirewallRules(desired state.State, spec profile.Spec) []firewall.Rule {
	rules := firewall.Rules(spec)
	if !desired.Bot.Enabled {
		return rules
	}
	port := desired.Bot.SubscriptionPort
	if port == 0 {
		port = deploy.DefaultBotSubPort
	}
	for _, rule := range rules {
		if rule.Port == port && rule.Network == "tcp" {
			return rules
		}
	}
	rules = append(rules, firewall.Rule{Port: port, Network: "tcp", Comment: "spaiter-vpn subscription"})
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Port != rules[j].Port {
			return rules[i].Port < rules[j].Port
		}
		return rules[i].Network < rules[j].Network
	})
	return rules
}
