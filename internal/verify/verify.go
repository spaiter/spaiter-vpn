// Package verify proves a user's methods work end to end: it runs the core as
// a client of the user's own subscription bundle and asks it to send a real
// request through every node.
//
// It replaces guide/test_protos.py, which rebuilt each client config by hand
// from server state and so tested its own reconstruction as much as the
// server. The bundle is what clients actually receive.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result is one node's outcome.
type Result struct {
	Node    string
	Type    string
	Delay   time.Duration
	Error   string
	Skipped string
}

// groups carry no tunnel of their own and are dropped from the client.
var groups = map[string]bool{"selector": true, "urltest": true}

// passthrough are outbound types that are not tunnels to the server.
var passthrough = map[string]bool{"direct": true, "block": true, "dns": true}

// clientOnly are bundle node types the server's core cannot run as a client,
// with why; they are reported, not failed.
var clientOnly = map[string]string{
	"wdtt":  "only the client fork implements wdtt",
	"chain": "only the client fork implements chain",
	// The naive client needs cronet, which the server build leaves out.
	"naive": "the server core is built without the naive client",
}

// awgKeys are the AmneziaWG parameters a bundle carries flat on the node and
// the core's endpoint expects nested under "awg".
var awgKeys = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5", "header_protection_key", "content_padding_addition",
	"rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout",
	"max_handshake_attempts", "random_trailers", "disable_cookies",
}

// ClientConfig turns a subscription bundle into a config the core can run as
// a headless client: no inbounds, so no TUN and no privileges, and a clash API
// on controller to measure each node through. The bundle is written for the
// client fork, so AmneziaWG nodes are reshaped into the core's endpoint form
// and node types only the fork implements are left out and reported.
func ClientConfig(bundle []byte, controller string) ([]byte, []Result, error) {
	return clientConfig(bundle, controller, exclusions{})
}

// exclusions are what an earlier start of the core refused: node types it
// does not know, and nodes that failed as it started. Each is left out of the
// next start, so one node cannot hide the result of every other.
type exclusions struct {
	kinds map[string]string
	tags  map[string]string
}

func clientConfig(bundle []byte, controller string, left exclusions) ([]byte, []Result, error) {
	unknown := left.kinds
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse the subscription bundle: %w", err)
	}
	outbounds, _ := doc["outbounds"].([]any)
	endpoints, _ := doc["endpoints"].([]any)
	var keptOutbounds, keptEndpoints []any
	var nodes []Result
	skippedTags := map[string]bool{}
	for _, raw := range outbounds {
		node, _ := raw.(map[string]any)
		tag, _ := node["tag"].(string)
		kind, _ := node["type"].(string)
		switch {
		case groups[kind]:
			continue
		case left.tags[tag] != "":
			skippedTags[tag] = true
			nodes = append(nodes, Result{Node: tag, Type: kind, Error: left.tags[tag]})
			continue
		case passthrough[kind]:
			keptOutbounds = append(keptOutbounds, node)
			continue
		case clientOnly[kind] != "" || unknown[kind] != "":
			reason := clientOnly[kind]
			if reason == "" {
				reason = unknown[kind]
			}
			skippedTags[tag] = true
			nodes = append(nodes, Result{Node: tag, Type: kind, Skipped: reason})
			continue
		case kind == "mieru":
			// The fork takes server_port plus transport; the core takes
			// port bindings and refuses the fork's field.
			if port, ok := node["server_port"]; ok {
				transport, _ := node["transport"].(string)
				if transport == "" {
					transport = "TCP"
				}
				node["portBindings"] = []any{map[string]any{"protocol": transport, "port": port}}
				delete(node, "server_port")
			}
			delete(node, "transport")
			keptOutbounds = append(keptOutbounds, node)
		case kind == "awg":
			nested := map[string]any{}
			for _, key := range awgKeys {
				if value, ok := node[key]; ok {
					nested[key] = value
					delete(node, key)
				}
			}
			if len(nested) > 0 {
				node["awg"] = nested
			}
			keptEndpoints = append(keptEndpoints, node)
		default:
			keptOutbounds = append(keptOutbounds, node)
		}
		nodes = append(nodes, Result{Node: tag, Type: kind})
	}
	for _, raw := range endpoints {
		node, _ := raw.(map[string]any)
		tag, _ := node["tag"].(string)
		kind, _ := node["type"].(string)
		if unknown[kind] != "" {
			skippedTags[tag] = true
			nodes = append(nodes, Result{Node: tag, Type: kind, Skipped: unknown[kind]})
			continue
		}
		if left.tags[tag] != "" {
			skippedTags[tag] = true
			nodes = append(nodes, Result{Node: tag, Type: kind, Error: left.tags[tag]})
			continue
		}
		keptEndpoints = append(keptEndpoints, node)
		nodes = append(nodes, Result{Node: tag, Type: kind})
	}
	// A node chained through one that was left out cannot run either, nor
	// can anything chained through it, so it leaves the config too: a detour
	// to a missing tag stops the core from starting.
	for changed := true; changed; {
		changed = false
		for _, list := range []*[]any{&keptOutbounds, &keptEndpoints} {
			kept := (*list)[:0]
			for _, raw := range *list {
				node, _ := raw.(map[string]any)
				tag, _ := node["tag"].(string)
				detour, _ := node["detour"].(string)
				if detour != "" && skippedTags[detour] {
					skippedTags[tag], changed = true, true
					for i := range nodes {
						if nodes[i].Node == tag && nodes[i].Skipped == "" && nodes[i].Error == "" {
							nodes[i].Skipped = "chained through " + detour
						}
					}
					continue
				}
				kept = append(kept, raw)
			}
			*list = kept
		}
	}
	tested := 0
	for _, node := range nodes {
		if node.Skipped == "" {
			tested++
		}
	}
	// A node that already failed counts as tested: it has a result.
	if tested == 0 {
		return nil, nil, fmt.Errorf("the bundle has no nodes this core can test")
	}
	doc["outbounds"] = keptOutbounds
	doc["endpoints"] = keptEndpoints
	doc["inbounds"] = []any{}
	delete(doc, "route")
	experimental, _ := doc["experimental"].(map[string]any)
	if experimental == nil {
		experimental = map[string]any{}
	}
	experimental["clash_api"] = map[string]any{"external_controller": controller}
	delete(experimental, "cache_file")
	doc["experimental"] = experimental
	doc["log"] = map[string]any{"level": "warn"}
	data, err := json.Marshal(doc)
	return data, nodes, err
}

// Process is a running client core.
type Process interface {
	Stop()
	// Logs is what the core printed, for a report when it did not start.
	Logs() string
	// Exited reports a core that is no longer running, so a refused config
	// is reported at once instead of after the start timeout.
	Exited() bool
}

// Runner starts the core as a client of a config file.
type Runner func(ctx context.Context, configPath string) (Process, error)

type dockerProcess struct{ name string }

func (p dockerProcess) Stop() { _ = exec.Command("docker", "rm", "-f", p.name).Run() }
func (p dockerProcess) Exited() bool {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", p.name).Output()
	return err == nil && strings.TrimSpace(string(out)) == "false"
}
func (p dockerProcess) Logs() string {
	out, _ := exec.Command("docker", "logs", p.name).CombinedOutput()
	return headTail(string(out))
}

// headTail keeps the start of a core's log, where it says why it refused to
// start, and its end, where it says how it stopped.
func headTail(log string) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) <= 60 {
		return log
	}
	return strings.Join(lines[:20], "\n") + fmt.Sprintf("\n... %d lines ...\n", len(lines)-60) + strings.Join(lines[len(lines)-40:], "\n") + "\n"
}

// DockerRunner runs the core image on the host network, which is how the
// client reaches the server's public address the same way a phone would. No
// --rm: a core that exits at once must leave its log to report.
func DockerRunner(image string) Runner {
	return func(ctx context.Context, configPath string) (Process, error) {
		name := fmt.Sprintf("spaiter-vpn-verify-%d", time.Now().UnixNano())
		cmd := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "--network", "host",
			"-v", configPath+":/etc/sing-box/client.json:ro", image, "run", "-c", "/etc/sing-box/client.json")
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("start the client core: %w: %s", err, out)
		}
		return dockerProcess{name: name}, nil
	}
}

type binaryProcess struct {
	cmd    *exec.Cmd
	output *lockedBuffer
	done   chan struct{}
}

func (p binaryProcess) Stop()        { _ = p.cmd.Process.Kill(); <-p.done }
func (p binaryProcess) Logs() string { return headTail(p.output.String()) }
func (p binaryProcess) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// lockedBuffer is written by the core while Logs reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// BinaryRunner runs a local core binary.
func BinaryRunner(binary string) Runner {
	return func(ctx context.Context, configPath string) (Process, error) {
		output := &lockedBuffer{}
		cmd := exec.CommandContext(ctx, binary, "run", "-c", configPath)
		cmd.Stdout, cmd.Stderr = output, output
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		return binaryProcess{cmd: cmd, output: output, done: done}, nil
	}
}

// unknownType matches the core refusing a node type it was built without.
var unknownType = regexp.MustCompile(`unknown (?:outbound|endpoint) type: "?([a-z0-9-]+)|([a-z0-9-]+) outbound is not included in this build`)

// failedStart matches the core giving up because one node failed as it
// started, such as a MASQUE-WG node in a core older than the one that dials
// it in the background.
var failedStart = regexp.MustCompile(`start (?:outbound|endpoint)/[a-z0-9-]+\[(.+?)\]: (.+)`)

// Run tests every node of bundle through target and returns one result each.
// A core that does not know a node type, older or built without it, has
// that type left out and reported; a node that fails as the core starts is
// reported as failed. Either way the core is started again without it.
func Run(ctx context.Context, bundle []byte, run Runner, target string, timeout time.Duration) ([]Result, error) {
	left := exclusions{kinds: map[string]string{}, tags: map[string]string{}}
	for {
		nodes, logs, err := runOnce(ctx, bundle, run, target, timeout, left)
		if err == nil {
			return nodes, nil
		}
		if match := unknownType.FindStringSubmatch(logs); match != nil && left.kinds[match[1]+match[2]] == "" {
			kind := match[1] + match[2]
			left.kinds[kind] = "this core does not implement " + kind
			continue
		}
		if match := failedStart.FindStringSubmatch(logs); match != nil && left.tags[match[1]] == "" {
			left.tags[match[1]] = "failed as the core started: " + strings.TrimSpace(match[2])
			continue
		}
		if nodes, isolated := isolate(ctx, bundle, run, target, timeout, left); isolated {
			return nodes, nil
		}
		return nil, err
	}
}

// isolate runs each node in a core of its own, for a core that stopped
// without saying which node made it stop (one that panics on shutdown loses
// its own error). It reports false when there is only one node to try, since
// that run already failed.
func isolate(ctx context.Context, bundle []byte, run Runner, target string, timeout time.Duration, left exclusions) ([]Result, bool) {
	_, all, err := clientConfig(bundle, "127.0.0.1:1", left)
	if err != nil {
		return nil, false
	}
	var testable []string
	for _, node := range all {
		if node.Skipped == "" && node.Error == "" {
			testable = append(testable, node.Node)
		}
	}
	if len(testable) < 2 {
		return nil, false
	}
	results := map[string]Result{}
	for _, node := range all {
		results[node.Node] = node
	}
	for _, only := range testable {
		alone := exclusions{kinds: left.kinds, tags: map[string]string{}}
		for tag, reason := range left.tags {
			alone.tags[tag] = reason
		}
		for _, other := range testable {
			if other != only {
				alone.tags[other] = "isolated"
			}
		}
		nodes, _, err := runOnce(ctx, bundle, run, target, timeout, alone)
		if err != nil {
			result := results[only]
			result.Error = "the core stopped with only this node: " + firstLine(err.Error())
			results[only] = result
			continue
		}
		for _, node := range nodes {
			if node.Node == only {
				results[only] = node
			}
		}
	}
	out := make([]Result, 0, len(results))
	for _, result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out, true
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	return line
}

func runOnce(ctx context.Context, bundle []byte, run Runner, target string, timeout time.Duration, left exclusions) ([]Result, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	controller := listener.Addr().String()
	listener.Close()

	config, nodes, err := clientConfig(bundle, controller, left)
	if err != nil {
		return nil, "", err
	}
	dir, err := os.MkdirTemp("", "spaiter-vpn-verify-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	// The bundle holds the user's credentials.
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, config, 0o644); err != nil {
		return nil, "", err
	}
	process, err := run(ctx, path)
	if err != nil {
		return nil, "", err
	}
	defer process.Stop()

	base := "http://" + controller
	client := &http.Client{Timeout: timeout + 5*time.Second}
	if err := waitReady(ctx, client, base, process); err != nil {
		logs := process.Logs()
		return nil, logs, fmt.Errorf("%w\n%s", err, logs)
	}
	for i := range nodes {
		if nodes[i].Skipped != "" || nodes[i].Error != "" {
			continue
		}
		nodes[i].Delay, err = delay(ctx, client, base, nodes[i].Node, target, timeout)
		if err != nil {
			nodes[i].Error = err.Error()
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Node < nodes[j].Node })
	return nodes, "", nil
}

func waitReady(ctx context.Context, client *http.Client, base string, process Process) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/version", nil)
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			return nil
		}
		if process.Exited() {
			return fmt.Errorf("the client core exited")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the client core did not start: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func delay(ctx context.Context, client *http.Client, base, node, target string, timeout time.Duration) (time.Duration, error) {
	query := url.Values{"url": {target}, "timeout": {fmt.Sprint(timeout.Milliseconds())}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/proxies/"+url.PathEscape(node)+"/delay?"+query.Encode(), nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	var answer struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &answer)
	if response.StatusCode != http.StatusOK || answer.Delay <= 0 {
		if answer.Message == "" {
			answer.Message = fmt.Sprintf("HTTP %d", response.StatusCode)
		}
		return 0, fmt.Errorf("%s", answer.Message)
	}
	return time.Duration(answer.Delay) * time.Millisecond, nil
}
