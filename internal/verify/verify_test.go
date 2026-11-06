package verify

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const bundle = `{"inbounds":[{"type":"tun"}],"outbounds":[
 {"type":"urltest","tag":"🚀 Авто","outbounds":["VLESS Reality"]},{"type":"vless","tag":"VLESS Reality"},{"type":"tuic","tag":"TUIC"},
 {"type":"awg","tag":"AmneziaWG","private_key":"k","jc":4,"h1":"1"},{"type":"wdtt","tag":"WG-over-VK"},{"type":"direct","tag":"direct"}],
 "route":{"final":"🚀 Авто"},"experimental":{"cache_file":{"enabled":true}}}`

func TestTheClientConfigNeedsNoPrivilegeAndListsEveryTunnel(t *testing.T) {
	config, nodes, err := ClientConfig([]byte(bundle), "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.Unmarshal(config, &doc)
	if inbounds := doc["inbounds"].([]any); len(inbounds) != 0 {
		t.Fatal("the client keeps a TUN inbound, which needs privilege")
	}
	endpoints := doc["endpoints"].([]any)
	awg := endpoints[0].(map[string]any)
	nested, _ := awg["awg"].(map[string]any)
	if len(endpoints) != 1 || awg["tag"] != "AmneziaWG" || nested["jc"] != float64(4) || awg["jc"] != nil {
		t.Fatalf("AmneziaWG was not reshaped into the core's endpoint form: %v", endpoints)
	}
	for _, raw := range doc["outbounds"].([]any) {
		if kind := raw.(map[string]any)["type"]; kind == "urltest" || kind == "wdtt" || kind == "awg" {
			t.Fatalf("outbound %v stayed in a config the core cannot run", kind)
		}
	}
	skipped := 0
	for _, node := range nodes {
		if node.Skipped != "" {
			skipped++
			if node.Node != "WG-over-VK" {
				t.Fatalf("%s was skipped", node.Node)
			}
		}
	}
	if len(nodes) != 4 || skipped != 1 {
		t.Fatalf("nodes = %+v", nodes)
	}
}

// fakeCore answers like the core's clash API: TUIC fails, the rest pass.
func fakeCore(t *testing.T) Runner {
	return func(_ context.Context, path string) (Process, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Experimental struct {
				ClashAPI struct {
					Controller string `json:"external_controller"`
				} `json:"clash_api"`
			} `json:"experimental"`
		}
		json.Unmarshal(data, &doc)
		listener, err := net.Listen("tcp", doc.Experimental.ClashAPI.Controller)
		if err != nil {
			return nil, err
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/version":
				w.Write([]byte(`{}`))
			case strings.Contains(r.URL.Path, "TUIC"):
				w.WriteHeader(http.StatusGatewayTimeout)
				w.Write([]byte(`{"message":"timeout"}`))
			default:
				w.Write([]byte(`{"delay":42}`))
			}
		})}
		go server.Serve(listener)
		return fakeProcess{server}, nil
	}
}

func TestEveryNodeIsMeasuredThroughTheCore(t *testing.T) {
	results, err := Run(context.Background(), []byte(bundle), fakeCore(t), "https://example.com/", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("results = %+v", results)
	}
	for _, r := range results {
		switch r.Node {
		case "WG-over-VK":
			if r.Skipped == "" || r.Delay != 0 {
				t.Errorf("a client-only node was measured: %+v", r)
			}
		case "TUIC":
			if r.Error != "timeout" {
				t.Errorf("TUIC = %+v", r)
			}
		default:
			if r.Error != "" || r.Delay != 42*time.Millisecond {
				t.Errorf("%s = %+v", r.Node, r)
			}
		}
	}
}

type fakeProcess struct{ server *http.Server }

func (p fakeProcess) Stop()        { p.server.Close() }
func (p fakeProcess) Logs() string { return "" }
func (p fakeProcess) Exited() bool { return false }

type deadProcess struct{ logs string }

func (p deadProcess) Stop()        {}
func (p deadProcess) Logs() string { return p.logs }
func (p deadProcess) Exited() bool { return true }

func TestANodeTypeTheCoreDoesNotKnowIsSkippedNotFatal(t *testing.T) {
	fake := fakeCore(t)
	starts := 0
	older := func(ctx context.Context, path string) (Process, error) {
		starts++
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), `"tuic"`) {
			return deadProcess{"FATAL[0000] create outbound[1]: unknown outbound type: tuic"}, nil
		}
		return fake(ctx, path)
	}
	results, err := Run(context.Background(), []byte(bundle), older, "https://example.com/", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if starts != 2 {
		t.Fatalf("the core was started %d times", starts)
	}
	for _, r := range results {
		if r.Node == "TUIC" && r.Skipped == "" {
			t.Fatalf("TUIC = %+v", r)
		}
		if r.Node == "VLESS Reality" && r.Delay != 42*time.Millisecond {
			t.Fatalf("VLESS = %+v", r)
		}
	}
}

func TestANodeChainedThroughASkippedOneLeavesTheConfig(t *testing.T) {
	chained := `{"outbounds":[{"type":"wdtt","tag":"WG-over-VK"},
 {"type":"vless","tag":"VLESS via VK","detour":"WG-over-VK"},{"type":"vless","tag":"Deeper","detour":"VLESS via VK"},
 {"type":"vless","tag":"VLESS Reality"}]}`
	config, nodes, err := ClientConfig([]byte(chained), "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "VLESS via VK") || strings.Contains(string(config), "Deeper") {
		t.Fatalf("a node whose detour is gone stayed in the config, which the core refuses to start: %s", config)
	}
	for _, node := range nodes {
		if (node.Node == "VLESS Reality") != (node.Skipped == "") {
			t.Fatalf("%+v", nodes)
		}
	}
}

func TestALongCoreLogKeepsWhyItStoppedAndHowItEnded(t *testing.T) {
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "line")
	}
	lines[0], lines[199] = "FATAL start", "panic at close"
	got := headTail(strings.Join(lines, "\n"))
	if !strings.Contains(got, "FATAL start") || !strings.Contains(got, "panic at close") || strings.Count(got, "\n") > 62 {
		t.Fatalf("%s", got)
	}
}

func TestANodeThatFailsAsTheCoreStartsFailsAloneAndTheRestAreMeasured(t *testing.T) {
	fake := fakeCore(t)
	refusing := func(ctx context.Context, path string) (Process, error) {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), `"tag":"VLESS Reality"`) {
			return deadProcess{"FATAL[0000] start service: finish-start outbound/vless[VLESS Reality]: dial: x509: no IP SANs"}, nil
		}
		return fake(ctx, path)
	}
	results, err := Run(context.Background(), []byte(bundle), refusing, "https://example.com/", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		switch r.Node {
		case "VLESS Reality":
			if !strings.Contains(r.Error, "no IP SANs") {
				t.Errorf("VLESS = %+v", r)
			}
		case "AmneziaWG":
			if r.Delay != 42*time.Millisecond {
				t.Errorf("AmneziaWG was not measured once VLESS was left out: %+v", r)
			}
		}
	}
}

func TestACoreThatStopsWithoutSayingWhyIsTriedOneNodeAtATime(t *testing.T) {
	fake := fakeCore(t)
	silent := func(ctx context.Context, path string) (Process, error) {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), `"type":"tuic"`) {
			return deadProcess{"panic: nil pointer dereference in Close"}, nil
		}
		return fake(ctx, path)
	}
	results, err := Run(context.Background(), []byte(bundle), silent, "https://example.com/", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		switch r.Node {
		case "TUIC":
			if !strings.Contains(r.Error, "only this node") {
				t.Errorf("TUIC = %+v", r)
			}
		case "VLESS Reality", "AmneziaWG":
			if r.Delay != 42*time.Millisecond {
				t.Errorf("%s = %+v", r.Node, r)
			}
		}
	}
}
