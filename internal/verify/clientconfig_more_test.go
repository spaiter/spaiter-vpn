package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientConfigRefusesWhatIsNotABundleOrHasNothingToTest(t *testing.T) {
	if _, _, err := ClientConfig([]byte("{"), "127.0.0.1:9090"); err == nil || !strings.Contains(err.Error(), "parse the subscription bundle") {
		t.Errorf("garbage: %v", err)
	}
	// Only a node type the fork alone implements: nothing is left to measure.
	for kind := range clientOnly {
		bundle := `{"outbounds":[{"type":"` + kind + `","tag":"only"}]}`
		if _, _, err := ClientConfig([]byte(bundle), "127.0.0.1:9090"); err == nil || !strings.Contains(err.Error(), "no nodes this core can test") {
			t.Errorf("%s only: %v", kind, err)
		}
		break
	}
}

func TestMieruIsReshapedToPortBindingsWithATCPDefault(t *testing.T) {
	bundle := `{"outbounds":[
		{"type":"mieru","tag":"m1","server":"h","server_port":1000,"transport":"UDP"},
		{"type":"mieru","tag":"m2","server":"h","server_port":2000},
		{"type":"mieru","tag":"m3","server":"h","transport":"TCP"}
	]}`
	config, nodes, err := ClientConfig([]byte(bundle), "127.0.0.1:9090")
	if err != nil || len(nodes) != 3 {
		t.Fatalf("nodes = %v, err = %v", nodes, err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(config, &doc); err != nil {
		t.Fatal(err)
	}
	byTag := map[string]map[string]any{}
	for _, o := range doc.Outbounds {
		byTag[o["tag"].(string)] = o
	}
	first := byTag["m1"]["portBindings"].([]any)[0].(map[string]any)
	second := byTag["m2"]["portBindings"].([]any)[0].(map[string]any)
	if first["protocol"] != "UDP" || second["protocol"] != "TCP" || first["port"] != float64(1000) {
		t.Errorf("bindings = %v / %v", first, second)
	}
	for tag, o := range byTag {
		if _, ok := o["server_port"]; ok {
			t.Errorf("%s kept the fork's field", tag)
		}
		if _, ok := o["transport"]; ok {
			t.Errorf("%s kept the transport", tag)
		}
	}
	if _, ok := byTag["m3"]["portBindings"]; ok {
		t.Error("a node with no port gained bindings")
	}
}

func TestEarlierFailuresLeaveTheirNodesOutOfTheNextStart(t *testing.T) {
	bundle := `{"outbounds":[
		{"type":"vless","tag":"good"},
		{"type":"vless","tag":"broken"},
		{"type":"strange","tag":"odd"},
		{"type":"vless","tag":"via-broken","detour":"broken"}
	],"endpoints":[
		{"type":"awg","tag":"ep-ok"},
		{"type":"awg","tag":"ep-broken"},
		{"type":"alien","tag":"ep-alien"}
	]}`
	left := exclusions{
		kinds: map[string]string{"strange": "unknown to this core", "alien": "unknown endpoint"},
		tags:  map[string]string{"broken": "failed as the core started", "ep-broken": "bad key"},
	}
	config, nodes, err := clientConfig([]byte(bundle), "127.0.0.1:9090", left)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Result{}
	for _, n := range nodes {
		by[n.Node] = n
	}
	if by["broken"].Error == "" || by["odd"].Skipped == "" || by["ep-broken"].Error == "" || by["ep-alien"].Skipped == "" {
		t.Errorf("exclusions not recorded: %+v", by)
	}
	if !strings.Contains(by["via-broken"].Skipped, "chained through broken") {
		t.Errorf("chained node = %+v", by["via-broken"])
	}
	for _, kept := range []string{`"good"`, `"ep-ok"`} {
		if !strings.Contains(string(config), kept) {
			t.Errorf("%s was dropped", kept)
		}
	}
	for _, dropped := range []string{`"broken"`, `"odd"`, `"ep-broken"`, `"ep-alien"`, `"via-broken"`} {
		if strings.Contains(string(config), dropped) {
			t.Errorf("%s stayed in the config", dropped)
		}
	}
}
