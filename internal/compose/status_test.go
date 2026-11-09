package compose

import "testing"

// TestParseServicesAcceptsBothComposeShapes. `docker compose ps --format json`
// prints a JSON array on newer Compose and one object per line on older ones.
// Handling a single shape would make the health wait fail on hosts that are
// otherwise fine, and the failure would look like an unhealthy deployment.
func TestParseServicesAcceptsBothComposeShapes(t *testing.T) {
	array := `[{"Service":"sing-box","Name":"sing-box","State":"running","Health":"","ExitCode":0},
	           {"Service":"vpn-bot","Name":"vpn-bot","State":"exited","Health":"","ExitCode":1}]`
	lines := `{"Service":"sing-box","Name":"sing-box","State":"running","Health":"","ExitCode":0}
{"Service":"vpn-bot","Name":"vpn-bot","State":"exited","Health":"","ExitCode":1}`

	for name, data := range map[string]string{"array": array, "ndjson": lines} {
		states, err := parseServices([]byte(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(states) != 2 {
			t.Fatalf("%s: got %d services, want 2", name, len(states))
		}
		if !states[0].Running() {
			t.Errorf("%s: a running service was not reported as running", name)
		}
		if states[1].Running() || states[1].ExitCode != 1 {
			t.Errorf("%s: exited service = %#v", name, states[1])
		}
	}

	if states, err := parseServices([]byte("  \n")); err != nil || states != nil {
		t.Fatalf("empty output: states=%#v err=%v", states, err)
	}
}

// TestRestartingIsNotRunning pins the distinction the health wait depends on. A
// crash-looping container reports "restarting", and treating anything but
// "exited" as up is how a restart loop passes for a successful start.
func TestRestartingIsNotRunning(t *testing.T) {
	for _, state := range []string{"restarting", "exited", "created", "paused", "dead", "removing"} {
		if (ServiceState{Service: "x", State: state}).Running() {
			t.Errorf("state %q was accepted as running", state)
		}
	}
	// Compose has reported the state capitalised; the check must not depend on
	// that, or the wait silently never settles on such a host.
	if !(ServiceState{Service: "x", State: "Running"}).Running() {
		t.Error("a capitalised running state was rejected")
	}
	// An unhealthy healthcheck is not up either, whatever the state says.
	if (ServiceState{Service: "x", State: "running", Health: "unhealthy"}).Running() {
		t.Error("an unhealthy service was accepted as running")
	}
}
