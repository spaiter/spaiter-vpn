package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// Seams for tests: where the port questions are read from, and whether that
// is somebody at a terminal.
var (
	promptInput      io.Reader = os.Stdin
	promptIsTerminal           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
)

// newPrompt is the reader every installation question shares, or nil when
// stdin is not a terminal and there is nobody to answer. One reader, because a
// second one over the same stdin would lose whatever the first had buffered.
func newPrompt() *bufio.Reader {
	if !promptIsTerminal() {
		return nil
	}
	return bufio.NewReader(promptInput)
}

// portItem is one listener whose port a fresh install chooses.
type portItem struct {
	name     string // what the operator sees: the protocol tag, or "bot subscription"
	networks string // "tcp", "udp" or "tcp+udp": what a port forward needs
	port     uint16
	fixed    bool // given on the command line: shown, never asked
}

// protocolPortItems lists protocols in a stable order, with their transports.
func protocolPortItems(protocols []profile.Protocol, ports map[profile.Protocol]uint16, fixed map[profile.Protocol]bool) []portItem {
	ordered := append([]profile.Protocol(nil), protocols...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	items := make([]portItem, 0, len(ordered))
	for _, p := range ordered {
		items = append(items, portItem{
			name:     string(p),
			networks: strings.Join(p.Networks(), "+"),
			port:     ports[p],
			fixed:    fixed[p],
		})
	}
	return items
}

// choosePorts shows the proposed ports and lets the operator keep them or
// change any of them. Without a terminal there is nobody to ask, so the
// proposal stands and is only printed: cloud-init and scripts get random
// ports, not a prompt that hangs.
//
// in is nil when there is no terminal (see newPrompt).
func choosePorts(in *bufio.Reader, out io.Writer, items []portItem) error {
	printPorts(out, items)
	if in == nil {
		return nil
	}
	answer, err := ask(in, out, "Use these ports? [Y/n] ")
	if err != nil || answer == "" || strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		return err
	}
	fmt.Fprintf(out, "Enter a port for each, or press Enter to keep the one shown.\n")
	for i := range items {
		if items[i].fixed {
			continue
		}
		for attempt := 0; ; attempt++ {
			if attempt == 5 {
				return fmt.Errorf("%w: no valid port for %s after 5 attempts", ErrUsage, items[i].name)
			}
			answer, err := ask(in, out, fmt.Sprintf("  %s (%s) [%d]: ", items[i].name, items[i].networks, items[i].port))
			if err != nil {
				return err
			}
			if answer == "" {
				break
			}
			port, perr := parsePort(answer)
			if perr != nil {
				fmt.Fprintf(out, "  %v\n", perr)
				continue
			}
			if other := portOwner(items, port, i); other != "" {
				fmt.Fprintf(out, "  %d is already %s's\n", port, other)
				continue
			}
			items[i].port = port
			break
		}
	}
	printPorts(out, items)
	return nil
}

// ask reads one trimmed line. End of input keeps the remaining proposals, as
// pressing Enter would.
func ask(in *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	line, err := in.ReadString('\n')
	if errors.Is(err, io.EOF) {
		fmt.Fprintln(out)
		return strings.TrimSpace(line), nil
	}
	return strings.TrimSpace(line), err
}

func portOwner(items []portItem, port uint16, except int) string {
	for j, item := range items {
		if j != except && item.port == port {
			return item.name
		}
	}
	return ""
}

func printPorts(out io.Writer, items []portItem) {
	fmt.Fprintf(out, "Ports (drawn at random, so this server does not share a port set with every other install):\n")
	for _, item := range items {
		note := ""
		if item.fixed {
			note = "  (given)"
		}
		fmt.Fprintf(out, "  %-20s %-8s %5d%s\n", item.name, item.networks, item.port, note)
	}
}
