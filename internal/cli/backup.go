package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/spaiter/spaiter-vpn/internal/backup"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// Seams for tests: the passphrase prompt, and whether stdout is a terminal.
var (
	readPassphrase   = readPassphraseFromTTY
	stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	runningAsRoot    = func() bool { return os.Geteuid() == 0 }
)

// readPassphraseFromTTY reads from the controlling terminal rather than stdin
// and writes the prompt to stderr: stdout is where the archive goes.
func readPassphraseFromTTY(prompt string) (string, error) {
	tty, err := openTerminal()
	if err != nil {
		return "", fmt.Errorf("no terminal to ask for a passphrase on; pass -recipient or -passphrase-file")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	secret, err := readHidden(tty)
	fmt.Fprintln(tty)
	return string(secret), err
}

// readHidden reads one line from the terminal without echoing it. A variable
// so a test, which has no real terminal to switch the echo off on, can answer.
var readHidden = func(tty io.ReadWriteCloser) ([]byte, error) {
	file, ok := tty.(*os.File)
	if !ok {
		return nil, errors.New("the terminal has no file descriptor to switch the echo off on")
	}
	return term.ReadPassword(int(file.Fd()))
}

func readFirstLine(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return line, nil
}

// minPassphrase is short enough to type and long enough that the archive is
// not opened by guessing: scrypt slows each guess, it does not make a short
// passphrase long.
const minPassphrase = 12

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func runBackup(_ context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	var recipients stringList
	fs := newFlagSet("backup", out)
	output := fs.String("o", "", "write the archive to FILE instead of stdout")
	fs.Var(&recipients, "recipient", "age public key (age1...) to encrypt for; repeatable")
	recipientsFile := fs.String("recipients-file", "", "file of age public keys, one per line")
	passphraseFile := fs.String("passphrase-file", "", "read the passphrase from the first line of FILE instead of asking")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn backup [-recipient age1...] [-o FILE]\n\n")
		fmt.Fprintf(out, "Writes an encrypted backup of this deployment: the desired state, stored\n")
		fmt.Fprintf(out, "credentials, every key and user (including the ones the bot added), the\n")
		fmt.Fprintf(out, "traffic accounting, the bot's state and the ACME account. `restore` brings\n")
		fmt.Fprintf(out, "it up on a new server with the same keys, so clients keep working.\n\n")
		fmt.Fprintf(out, "Keep it away from this provider. A copy the provider holds is lost with\n")
		fmt.Fprintf(out, "the account, and a hoster's own backups have been wiped in a breach. Pipe\n")
		fmt.Fprintf(out, "it straight to another machine, so no copy stays here:\n\n")
		fmt.Fprintf(out, "  ssh root@server spaiter-vpn backup -recipient age1... > vpn-backup.age\n\n")
		fmt.Fprintf(out, "Without -recipient it asks for a passphrase. The archive is age-encrypted:\n")
		fmt.Fprintf(out, "`age -d` opens it without this binary.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if !runningAsRoot() {
		return fmt.Errorf("the backup reads every private key of the deployment, so it needs root:\n\n  sudo %s backup %s\n", selfPathOrName(), strings.Join(args, " "))
	}

	encryptTo, err := backupRecipients(recipients, *recipientsFile, *passphraseFile)
	if err != nil {
		return err
	}

	snap, err := backup.Collect(layout, Version)
	if err != nil {
		return err
	}

	var w io.Writer = out
	var file *os.File
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		w = file
	} else if out == io.Writer(os.Stdout) && stdoutIsTerminal() {
		return fmt.Errorf("%w: the archive is binary; redirect it to a file or pass -o FILE", ErrUsage)
	}
	if err := snap.Write(w, encryptTo...); err != nil {
		if file != nil {
			file.Close()
			os.Remove(*output)
		}
		return err
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return err
		}
	}
	var size int64
	for _, f := range snap.Files {
		size += f.Size
	}
	fmt.Fprintf(os.Stderr, "backup: %d files, %d KiB before compression, for %s\n", len(snap.Files), size/1024, snap.Manifest.PublicHost)
	fmt.Fprintln(os.Stderr, "Keep it off this provider; restore with `spaiter-vpn restore -from FILE` on a new server.")
	return nil
}

func backupRecipients(keys []string, keysFile, passphraseFile string) ([]age.Recipient, error) {
	if keysFile != "" {
		data, err := os.ReadFile(keysFile)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				keys = append(keys, line)
			}
		}
	}
	if len(keys) > 0 {
		if passphraseFile != "" {
			return nil, fmt.Errorf("%w: a passphrase and recipients cannot be combined; age encrypts to one or the other", ErrUsage)
		}
		var out []age.Recipient
		for _, key := range keys {
			r, err := age.ParseX25519Recipient(key)
			if err != nil {
				return nil, fmt.Errorf("recipient %q: %w", key, err)
			}
			out = append(out, r)
		}
		return out, nil
	}

	var passphrase string
	var err error
	if passphraseFile != "" {
		if passphrase, err = readFirstLine(passphraseFile); err != nil {
			return nil, err
		}
	} else {
		if passphrase, err = readPassphrase("Passphrase for the backup: "); err != nil {
			return nil, err
		}
		again, err := readPassphrase("Again: ")
		if err != nil {
			return nil, err
		}
		if again != passphrase {
			return nil, errors.New("the passphrases differ")
		}
	}
	if len(passphrase) < minPassphrase {
		return nil, fmt.Errorf("the passphrase is shorter than %d characters; it guards every key of the deployment", minPassphrase)
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	return []age.Recipient{r}, nil
}

func runRestore(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("restore", out)
	from := fs.String("from", "", "the backup archive")
	identityFile := fs.String("identity", "", "age identity file (AGE-SECRET-KEY-...) the backup was encrypted for")
	passphraseFile := fs.String("passphrase-file", "", "read the passphrase from the first line of FILE instead of asking")
	publicHost := fs.String("public-host", "", "the address clients dial from now on, when it is not the backup's")
	keepAddress := fs.Bool("keep-address", false, "keep the backup's address without asking (the address moved with the server)")
	yes := fs.Bool("yes", false, "apply without asking; required when stdin is not a terminal")
	strict := fs.Bool("strict", false, "treat preflight warnings as failures")
	singBoxBinary := fs.String("sing-box", "", "local sing-box binary to validate with instead of the image")
	defaults := health.DefaultOptions()
	deadline := fs.Duration("health-deadline", defaults.Deadline, "how long the started deployment has to become usable")
	settle := fs.Duration("health-settle", defaults.Settle, "how long it must stay usable before the generation is recorded")
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn restore -from FILE [-identity KEY] [-public-host H | -keep-address] [-yes]\n\n")
		fmt.Fprintf(out, "Brings a backup up on a new server: the same keys, users and subscriptions,\n")
		fmt.Fprintf(out, "rendered for this host and installed the way `bootstrap apply` installs,\n")
		fmt.Fprintf(out, "with its own firewall rules, units and receipt.\n\n")
		fmt.Fprintf(out, "Clients keep their keys. What may change is the address they dial. Behind a\n")
		fmt.Fprintf(out, "domain, point its record here (the built-in dynamic DNS does that by itself)\n")
		fmt.Fprintf(out, "and nobody notices. Behind a bare IP address every client config and every\n")
		fmt.Fprintf(out, "subscription link names the old one; restore asks for the new address, and\n")
		fmt.Fprintf(out, "the bot sends each subscriber the new link when it starts.\n\n")
		fmt.Fprintf(out, "Refuses a server that already has a deployment. An interrupted restore can\n")
		fmt.Fprintf(out, "be run again with the same archive.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return fmt.Errorf("%w: -from is required", ErrUsage)
	}
	if *publicHost != "" && *keepAddress {
		return fmt.Errorf("%w: -public-host and -keep-address contradict each other", ErrUsage)
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if *deadline <= 0 || *settle < 0 || *settle >= *deadline {
		return fmt.Errorf("%w: -health-settle must be shorter than -health-deadline and neither may be negative", ErrUsage)
	}
	in := newPrompt()
	if !*yes && in == nil {
		return errors.New("stdin is not a terminal, so there is nobody to confirm the plan; pass -yes")
	}
	if !runningAsRoot() {
		return fmt.Errorf("restore writes /etc, changes firewall rules and starts the deployment, so it needs root:\n\n  sudo %s restore %s\n", selfPathOrName(), strings.Join(args, " "))
	}

	snap, err := openBackup(*from, *identityFile, *passphraseFile)
	if err != nil {
		return err
	}
	desired, configJSON, secretsJSON, err := snap.Deployment()
	if err != nil {
		return err
	}
	m := snap.Manifest
	fmt.Fprintf(out, "Backup of %s, taken %s by %s: %d files.\n", m.Hostname, m.Created.Format("2006-01-02 15:04 MST"), m.Version, len(snap.Files))
	relayDir := desired.Bot.WDTTConfigDirectory
	if err := backup.CheckFresh(snap, layout, relayDir); err != nil {
		return err
	}

	moved, err := restoreAddress(ctx, in, out, &desired, *publicHost, *keepAddress)
	if err != nil {
		return err
	}
	if err := desired.Validate(); err != nil {
		return fmt.Errorf("the restored desired state is not valid: %w", err)
	}
	if desired.DDNS != nil {
		if _, err := os.Stat(credentialPath(layout, string(desired.DDNS.Token))); err != nil && snapHasNoCredential(snap, string(desired.DDNS.Token)) {
			return fmt.Errorf("dynamic DNS needs its token; store it and run restore again:\n\n  sudo %s bootstrap credential %s\n", selfPathOrName(), desired.DDNS.Token)
		}
	}

	written, err := backup.Place(snap, layout, relayDir)
	if err != nil {
		return fmt.Errorf("place the backed-up state: %w", err)
	}
	fmt.Fprintf(out, "Placed %d files: credentials, accounting, bot state and cache.\n\n", len(written))

	if err := newTransactionManager(layout).Recover(); err != nil {
		return fmt.Errorf("recover an interrupted transaction: %w", err)
	}
	approved, err := buildPlan(ctx, desired, layout)
	if err != nil {
		return err
	}
	writePlan(out, "the backup", approved)
	if approved.Blocked {
		return fmt.Errorf("the plan is blocked; resolve the items above and run restore again")
	}
	if approved.Mode != plan.ModeFresh {
		return fmt.Errorf("restore installs onto a fresh server, but the plan is %q", approved.Mode)
	}
	fmt.Fprintln(out, "\nNo key is generated: every credential comes from the backup.")
	if !*yes {
		confirmed, err := confirm(out, "\nRestore with this plan? Type yes to continue: ")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "nothing was installed; the placed state stays for the next attempt")
			return nil
		}
	}

	options, err := buildApplyOptions(ctx, layout, desired, approved, out, *strict, *singBoxBinary)
	if err != nil {
		return err
	}
	options.HealthTuning = health.Options{Deadline: *deadline, Settle: *settle}
	options.Restore = &apply.Restore{Config: configJSON, Secrets: secretsJSON}
	result, err := runApply(ctx, options)
	if err != nil {
		return err
	}
	writeResult(out, layout, desired, approved, result)
	if moved != "" {
		fmt.Fprintf(out, "\nClients were given %s and must now reach %s.\n", moved, desired.Bot.PublicHost)
		if desired.Bot.Enabled {
			fmt.Fprintln(out, "The bot sends every subscriber the new subscription link as it starts.")
		} else {
			fmt.Fprintln(out, "Hand every user a new config: `spaiter-vpn clients` renders them.")
		}
	}
	return nil
}

func credentialPath(layout discover.Layout, name string) string {
	return layout.CredentialDir() + "/" + name
}

func snapHasNoCredential(snap *backup.Snapshot, name string) bool {
	_, ok := snap.Lookup(backup.RootConfig, "credentials/"+name)
	return !ok
}

func openBackup(path, identityFile, passphraseFile string) (*backup.Snapshot, error) {
	var identities []age.Identity
	switch {
	case identityFile != "":
		f, err := os.Open(identityFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if identities, err = age.ParseIdentities(f); err != nil {
			return nil, fmt.Errorf("read %s: %w", identityFile, err)
		}
	default:
		passphrase := ""
		var err error
		if passphraseFile != "" {
			passphrase, err = readFirstLine(passphraseFile)
		} else {
			passphrase, err = readPassphrase("Passphrase of the backup: ")
		}
		if err != nil {
			return nil, err
		}
		identity, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, err
		}
		identities = []age.Identity{identity}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return backup.Read(bufio.NewReader(f), identities...)
}

// restoreAddress decides what clients dial after the restore and records it in
// desired. It returns the old address when it changed.
//
// A domain stays: its record is pointed here, by hand or by the dynamic DNS
// updater, and no client notices. An IP address is the hard case. Every client
// config and every subscription link holds it, so moving to another server
// means every user has to be handed a new link; that is said plainly, with the
// suggestion that this is the moment to put a domain in front.
func restoreAddress(ctx context.Context, in *bufio.Reader, out io.Writer, desired *state.State, given string, keep bool) (string, error) {
	old := desired.Bot.PublicHost
	if keep || old == "" {
		return "", nil
	}
	if given != "" {
		if given == old {
			return "", nil
		}
		address, err := choosePublicAddress(ctx, nil, out, given, desired.Bot.DynamicIP, false)
		if err != nil {
			return "", err
		}
		setAddress(desired, old, address)
		return old, nil
	}
	if _, err := netip.ParseAddr(old); err != nil {
		// A name: it follows the server wherever its record points.
		warnIfNotHere(ctx, out, old)
		if desired.DDNS != nil {
			fmt.Fprintf(out, "The dynamic DNS updater points %s here once the deployment runs.\n", old)
		} else {
			fmt.Fprintf(out, "Point %s at this server; clients keep working without any change.\n", old)
		}
		return "", nil
	}
	for _, local := range localAddrs() {
		if local.String() == old {
			fmt.Fprintf(out, "This server has the backup's address %s; clients keep working.\n", old)
			return "", nil
		}
	}
	if in == nil {
		return "", fmt.Errorf("%w: the backup's clients dial %s, which is not an address of this server.\n"+
			"Pass -public-host with the new address (every user then needs the new link), or\n"+
			"-keep-address if the address moves to this server", ErrUsage, old)
	}
	fmt.Fprintf(out, "\nThe backup's clients dial %s, which is not an address of this server.\n", old)
	fmt.Fprintf(out, "Every client config and subscription link names it, so with a new address\n"+
		"every user needs a new link (the bot sends it). Behind a domain the next move\n"+
		"would go unnoticed, so this is a good moment to set one up.\n\n")
	answer, err := ask(in, out, fmt.Sprintf("Is %s moving to this server? [y/N] ", old))
	if err != nil {
		return "", err
	}
	if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		return "", nil
	}
	address, err := choosePublicAddress(ctx, in, out, "", false, true)
	if err != nil {
		return "", err
	}
	if address.host == "" {
		return "", fmt.Errorf("%w: no address was chosen", ErrUsage)
	}
	setAddress(desired, old, address)
	return old, nil
}

func setAddress(desired *state.State, old string, address publicAddress) {
	desired.Bot.PublicHost = address.host
	desired.Bot.DynamicIP = address.dynamic
	if address.ddns != nil {
		desired.DDNS = address.ddns
	}
	// The A-only name for the UDP methods was the old address too when it was
	// one; it follows. A name of its own is the operator's to repoint.
	if desired.Bot.PublicIPv4Host == old {
		desired.Bot.PublicIPv4Host = ""
		if ip, err := netip.ParseAddr(address.host); err == nil && ip.Is4() {
			desired.Bot.PublicIPv4Host = address.host
		}
	}
	if strings.HasPrefix(desired.Bot.DirectSubscriptionHost, old+":") {
		desired.Bot.DirectSubscriptionHost = ""
	}
}
