package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// atTerminal answers the port questions with input, as an operator would.
func atTerminal(t *testing.T, input string) {
	t.Helper()
	oldInput, oldTerminal := promptInput, promptIsTerminal
	promptInput = strings.NewReader(input)
	promptIsTerminal = func() bool { return true }
	t.Cleanup(func() { promptInput, promptIsTerminal = oldInput, oldTerminal })
}

func testItems() []portItem {
	return []portItem{
		{name: "vless-reality-in", networks: "tcp", port: 21000},
		{name: "awg-in", networks: "udp", port: 22000},
		{name: "bot subscription", networks: "tcp", port: 23000, fixed: true},
	}
}

func TestChoosePortsKeepsTheProposalOnEnter(t *testing.T) {
	atTerminal(t, "\n")
	items := testItems()
	if err := choosePorts(newPrompt(), &bytes.Buffer{}, items); err != nil {
		t.Fatal(err)
	}
	if items[0].port != 21000 || items[1].port != 22000 {
		t.Fatalf("ports changed: %+v", items)
	}
}

func TestChoosePortsEditsAndRejectsBadAnswers(t *testing.T) {
	// n to edit; vless: a word, a port out of range, the subscription's port
	// (taken), then 443; awg: Enter keeps it. The fixed item is never asked.
	atTerminal(t, "n\nabc\n70000\n23000\n443\n\n")
	items := testItems()
	var out bytes.Buffer
	if err := choosePorts(newPrompt(), &out, items); err != nil {
		t.Fatal(err)
	}
	if items[0].port != 443 || items[1].port != 22000 || items[2].port != 23000 {
		t.Fatalf("ports = %+v", items)
	}
	if !strings.Contains(out.String(), "23000 is already bot subscription's") {
		t.Errorf("a duplicate was not explained:\n%s", out.String())
	}
	if strings.Contains(out.String(), "bot subscription (tcp)") {
		t.Errorf("a given port was asked for:\n%s", out.String())
	}
}

func TestChoosePortsGivesUpAfterRepeatedBadAnswers(t *testing.T) {
	atTerminal(t, "n\nx\nx\nx\nx\nx\n")
	if err := choosePorts(newPrompt(), &bytes.Buffer{}, testItems()); err == nil {
		t.Fatal("five bad answers were accepted")
	}
}

func TestChoosePortsWithoutATerminalAsksNothing(t *testing.T) {
	oldTerminal := promptIsTerminal
	promptIsTerminal = func() bool { return false }
	t.Cleanup(func() { promptIsTerminal = oldTerminal })
	items := testItems()
	var out bytes.Buffer
	if err := choosePorts(newPrompt(), &out, items); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "[Y/n]") || !strings.Contains(out.String(), "21000") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func readDesired(t *testing.T, path string) state.State {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	desired, err := state.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return desired
}

// A fresh document must not carry the original deployment's port set, and
// two installs must not share one.
func TestBootstrapStateDrawsItsOwnPorts(t *testing.T) {
	dir := t.TempDir()
	var docs []state.State
	for i := range 2 {
		path := filepath.Join(dir, "desired"+string(rune('a'+i))+".json")
		if err := runBootstrapState(context.Background(), &bytes.Buffer{}, []string{"-users", "alice", "-o", path}); err != nil {
			t.Fatal(err)
		}
		docs = append(docs, readDesired(t, path))
	}
	defaults := profile.DefaultPorts()
	for i, doc := range docs {
		if len(doc.Deployment.Ports) != len(defaults) {
			t.Fatalf("document %d has %d ports, want %d", i, len(doc.Deployment.Ports), len(defaults))
		}
		same := 0
		for p, port := range doc.Deployment.Ports {
			if port < profile.RandomPortMin || port > profile.RandomPortMax {
				t.Errorf("document %d: %s = %d, outside the random range", i, p, port)
			}
			if defaults[p] == port {
				same++
			}
		}
		if same == len(defaults) {
			t.Errorf("document %d carries the reference port set", i)
		}
		if doc.Bot.SubscriptionPort == deploy.DefaultBotSubPort {
			t.Errorf("document %d kept the reference subscription port", i)
		}
	}
	a, _ := json.Marshal(docs[0].Deployment.Ports)
	b, _ := json.Marshal(docs[1].Deployment.Ports)
	if bytes.Equal(a, b) {
		t.Error("two documents drew the same ports")
	}
}

func TestBootstrapStateKeepsGivenPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired.json")
	args := []string{"-users", "alice", "-o", path, "-ports", "vless-reality-in=443,subscription=8443"}
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, args); err != nil {
		t.Fatal(err)
	}
	doc := readDesired(t, path)
	if doc.Deployment.Ports[profile.VLESSReality] != 443 || doc.Bot.SubscriptionPort != 8443 {
		t.Fatalf("ports = %v, subscription = %d", doc.Deployment.Ports, doc.Bot.SubscriptionPort)
	}
	for p, port := range doc.Deployment.Ports {
		if p != profile.VLESSReality && (port == 443 || port == 8443) {
			t.Errorf("%s drew a given port, %d", p, port)
		}
	}

	err := runBootstrapState(context.Background(), &bytes.Buffer{}, []string{"-users", "alice", "-o", path, "-ports", "nope=1"})
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("an unknown tag was accepted: %v", err)
	}
}

// The table must not end up inside a document written to stdout.
func TestBootstrapStateToStdoutStaysAValidDocument(t *testing.T) {
	var out bytes.Buffer
	if err := runBootstrapState(context.Background(), &out, []string{"-users", "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Decode(&out); err != nil {
		t.Fatalf("stdout is not a document: %v", err)
	}
}
