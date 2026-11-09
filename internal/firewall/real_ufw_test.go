package firewall

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRealUFW drives the host's ufw. It runs only with SPAITER_REAL_FIREWALL=1
// as root — which the throwaway-VM runner provides — because it adds and
// removes real rules on a firewall that is enforcing.
func TestRealUFW(t *testing.T) {
	if os.Getenv("SPAITER_REAL_FIREWALL") != "1" || os.Geteuid() != 0 {
		t.Skip("set SPAITER_REAL_FIREWALL=1 and run as root (done by run-unit-tests-in-vm.sh)")
	}
	if _, err := exec.LookPath("ufw"); err != nil {
		t.Skip("ufw is not installed")
	}
	ctx := context.Background()

	backend := Detect()
	if backend.Kind != UFW || !backend.Active {
		t.Fatalf("Detect = %+v, want an active ufw", backend)
	}

	applier, err := NewUFWApplier()
	if err != nil {
		t.Fatal(err)
	}
	if applier.Name() != "ufw" {
		t.Errorf("Name = %q", applier.Name())
	}

	tcp := Rule{Port: 41871, Network: "tcp", Comment: "spaiter-vpn test"}
	udp := Rule{Port: 41872, Network: "udp"}
	t.Cleanup(func() {
		_ = applier.Remove(ctx, tcp)
		_ = applier.Remove(ctx, udp)
	})
	rules := []Rule{tcp, udp}

	statuses, err := backend.Check(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if statuses[r.String()] != Blocked {
			t.Fatalf("%s before adding = %v, want Blocked", r, statuses[r.String()])
		}
	}
	if missing := Missing(rules, statuses); len(missing) != 2 {
		t.Errorf("Missing = %v, want both", missing)
	}
	if script := Script(backend, rules, statuses); !strings.Contains(script, "41871") || !strings.Contains(script, "41872") {
		t.Errorf("Script = %q, want both ports", script)
	}

	for i := 0; i < 2; i++ { // the second pass proves Add is idempotent
		for _, r := range rules {
			if err := applier.Add(ctx, r); err != nil {
				t.Fatalf("Add %s (pass %d): %v", r, i, err)
			}
		}
	}
	statuses, err = backend.Check(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if statuses[r.String()] != Allowed {
			t.Errorf("%s after adding = %v, want Allowed", r, statuses[r.String()])
		}
	}
	if missing := Missing(rules, statuses); len(missing) != 0 {
		t.Errorf("Missing after adding = %v", missing)
	}
	out, _ := exec.Command("ufw", "status").CombinedOutput()
	if !strings.Contains(string(out), "spaiter-vpn test") {
		t.Errorf("the comment did not reach ufw:\n%s", out)
	}

	// A rule read back from a receipt must remove what was added.
	parsed, err := ParseRule("41871/tcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.Remove(ctx, parsed); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	statuses, _ = backend.Check(rules)
	if statuses[tcp.String()] != Blocked || statuses[udp.String()] != Allowed {
		t.Errorf("after removing the tcp rule: %v", statuses)
	}

	if err := applier.Remove(ctx, Rule{Port: 41873, Network: "tcp"}); err == nil {
		// ufw reports "Could not delete non-existent rule" with status 0 on
		// some versions, so only a surprising failure shape is worth a note.
		t.Log("removing a rule that was never added succeeded")
	}

	// Existing rules are not disturbed: ssh from cloud-init is still there.
	statuses, _ = backend.Check([]Rule{{Port: 22, Network: "tcp"}})
	if statuses["22/tcp"] != Allowed {
		t.Errorf("22/tcp = %v, want Allowed", statuses["22/tcp"])
	}
}
