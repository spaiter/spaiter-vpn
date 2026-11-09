package selftest

import (
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/corelog"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

func TestProbeVerdictRequiresCorrectDetectionAndEnforcement(t *testing.T) {
	probes, err := Probes()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, want string }{
		{"success", ""}, {"empty-log", "no detection"}, {"other-inbound", "no detection"},
		{"wrong-detector", "expected"}, {"false-positive", "false positive"},
		{"missing-reject-debug", "no reject action"}, {"missing-reject-info", "enforcement cannot be proved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &Result{RouteDecisionsLogged: true, LogLevel: "debug", Rejections: []string{"reject"}}
			for _, p := range probes {
				if p.Detected() {
					result.Detections = append(result.Detections, corelog.Detection{Inbound: "test", DestinationPort: p.Port, Detector: p.Detector})
				}
			}
			switch tc.name {
			case "empty-log":
				result.Detections = nil
				result.Rejections = nil
			case "other-inbound":
				for i := range result.Detections {
					result.Detections[i].Inbound = "production"
				}
			case "wrong-detector":
				result.Detections[0].Detector = "unexpected"
			case "false-positive":
				result.Detections = append(result.Detections, corelog.Detection{Inbound: "test", DestinationPort: probes[0].Port, Detector: "dht"})
			case "missing-reject-debug":
				result.Rejections = nil
			case "missing-reject-info":
				result.Rejections = nil
				result.RouteDecisionsLogged = false
				result.LogLevel = "info"
			}
			err := assertProbes(io.Discard, "test", probes, result)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSelftestRefusesResourceCollisions(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"free", ""}, {"tag", "already has an endpoint"}, {"port", "already used"},
		{"overlap", "overlaps"}, {"public", "not private"}, {"too-small", "too small"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultOptions()
			live := &LiveConfig{EndpointPorts: map[string]uint16{"production": 10860}, EndpointAddresses: []string{"10.10.0.1/24"}}
			switch tc.name {
			case "tag":
				opts.Tag = "production"
			case "port":
				opts.Port = 10860
			case "overlap":
				opts.Subnet = netip.MustParsePrefix("10.10.0.0/25")
			case "public":
				opts.Subnet = netip.MustParsePrefix("8.8.8.0/24")
			case "too-small":
				opts.Subnet = netip.MustParsePrefix("10.99.0.0/30")
			}
			err := checkTestResourcesAreFree(live, opts)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAutomaticSubnetExhaustionFailsClosed(t *testing.T) {
	_, err := chooseTestSubnet(&LiveConfig{EndpointAddresses: []string{"10.0.0.1/8"}}, netip.MustParsePrefix("10.99.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), "no free automatic") {
		t.Fatalf("error = %v", err)
	}
}

func TestLiveConfigSelectsAPISecretAndProductionResources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"log":{"output":"/etc/sing-box/runtime.log","level":"debug"},"inbounds":[{"secret":"unrelated"}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090","secret":"api-only"}},"endpoints":[{"tag":"one","listen_port":10860,"address":"10.10.0.1/24"},{"tag":"two","listen_port":10861,"address":["10.20.0.1/24","fd00::1/64"]},{"tag":"outbound","address":[]}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	live, err := ReadLiveConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if live.ClashAPISecret != "api-only" || live.ClashAPIController != "127.0.0.1:9090" {
		t.Fatalf("wrong API settings: %+v", live)
	}
	if !reflect.DeepEqual(live.EndpointPorts, map[string]uint16{"one": 10860, "two": 10861}) {
		t.Fatalf("ports = %v", live.EndpointPorts)
	}
	if !reflect.DeepEqual(live.EndpointAddresses, []string{"10.10.0.1/24", "10.20.0.1/24", "fd00::1/64"}) {
		t.Fatalf("addresses = %v", live.EndpointAddresses)
	}
	if _, err := live.HostLogPath(); err == nil {
		t.Fatal("missing log accepted")
	}
	log := filepath.Join(filepath.Dir(path), "runtime.log")
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := live.HostLogPath(); err != nil || got != log {
		t.Fatalf("log = %q, %v", got, err)
	}
	live.LogOutput = ""
	if _, err := live.HostLogPath(); err == nil {
		t.Fatal("stdout treated as a file")
	}
	for _, level := range []string{"", "info", "warn", "debug", " TRACE "} {
		live.LogLevel = level
		want := level == "debug" || level == " TRACE "
		if live.RouteDecisionsAreLogged() != want {
			t.Errorf("observability at %q", level)
		}
	}
	for _, tag := range []string{"one", "absent"} {
		got, err := MentionsTag(path, tag)
		if err != nil || got != (tag == "one") {
			t.Fatalf("tag %q: %v %v", tag, got, err)
		}
	}
}

func TestLiveConfigReadErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := ReadLiveConfig(path); err == nil {
		t.Fatal("missing config accepted")
	}
	if _, err := MentionsTag(path, "test"); err == nil {
		t.Fatal("missing config treated as cleaned up")
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLiveConfig(path); err == nil {
		t.Fatal("malformed config accepted")
	}
}

func TestApplyMustNotDisturbProduction(t *testing.T) {
	for _, mode := range []string{"added", "missing", "recreated-endpoint", "reloaded-endpoint", "recreated-inbound", "reloaded-inbound", "added-inbound"} {
		t.Run(mode, func(t *testing.T) {
			result := &manage.ApplyResult{Endpoints: manage.ApplyOutcome{Added: []string{"test"}}}
			switch mode {
			case "missing":
				result.Endpoints.Added = nil
			case "recreated-endpoint":
				result.Endpoints.Recreated = []string{"production"}
			case "reloaded-endpoint":
				result.Endpoints.Reloaded = []string{"production"}
			case "recreated-inbound":
				result.Inbounds.Recreated = []string{"production"}
			case "reloaded-inbound":
				result.Inbounds.Reloaded = []string{"production"}
			case "added-inbound":
				result.Inbounds.Added = []string{"unexpected"}
			}
			err := assertOnlyAdded(result, "test")
			if (err == nil) != (mode == "added") {
				t.Fatalf("%s: %v", mode, err)
			}
		})
	}
}
