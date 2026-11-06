package selftest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LiveConfig is the part of a running instance's config.json that the
// self-test needs.
type LiveConfig struct {
	// Path is where the config was read from.
	Path string
	// LogOutput is log.output as written in the config, i.e. a path inside the
	// container.
	LogOutput string
	// LogLevel is log.level. It decides whether the result of this test can be
	// observed at all: the fork logs a BitTorrent detection at info, but the
	// routing decision that follows it — the reject — is logged at debug by the
	// router. At info the traffic is still dropped; there is simply no record
	// of the drop to read.
	LogLevel string
	// ClashAPIController is experimental.clash_api.external_controller.
	ClashAPIController string
	// ClashAPISecret is experimental.clash_api.secret.
	//
	// It is read as a JSON field rather than grepped for. That is not
	// fastidiousness: the config contains several unrelated fields named
	// "secret" — inbound passwords among them — and grepping builds a
	// multi-line Authorization header that the API answers with HTTP 400.
	ClashAPISecret string
	// EndpointPorts maps each existing endpoint tag to its listen port, so the
	// test can prove it disturbed none of them.
	EndpointPorts map[string]uint16
	// EndpointAddresses are the tunnel subnets already in use, so the test
	// subnet can be checked against them.
	EndpointAddresses []string
}

// ReadLiveConfig parses the running instance's configuration.
func ReadLiveConfig(path string) (*LiveConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("read %s: %w (the live config is root-owned 0600; run the self-test as root)", path, err)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var doc struct {
		Log struct {
			Output string `json:"output"`
			Level  string `json:"level"`
		} `json:"log"`
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
		Endpoints []struct {
			Tag        string          `json:"tag"`
			ListenPort uint16          `json:"listen_port"`
			Address    json.RawMessage `json:"address"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	live := &LiveConfig{
		Path:               path,
		LogOutput:          doc.Log.Output,
		LogLevel:           doc.Log.Level,
		ClashAPIController: doc.Experimental.ClashAPI.ExternalController,
		ClashAPISecret:     doc.Experimental.ClashAPI.Secret,
		EndpointPorts:      map[string]uint16{},
	}
	for _, ep := range doc.Endpoints {
		if ep.ListenPort != 0 {
			live.EndpointPorts[ep.Tag] = ep.ListenPort
		}
		live.EndpointAddresses = append(live.EndpointAddresses, decodeListable(ep.Address)...)
	}
	return live, nil
}

// RouteDecisionsAreLogged reports whether this configuration can show the
// routing decision that follows a detection.
//
// sing-box's level names are ordered trace < debug < info < warn < error <
// fatal, and the router logs matches with DebugContext. An empty level means
// the core's own default, which is info.
func (c *LiveConfig) RouteDecisionsAreLogged() bool {
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "trace", "debug":
		return true
	default:
		return false
	}
}

// HostLogPath translates the container-side log path into a host path.
//
// The container mounts the directory holding config.json at /etc/sing-box, so
// the log file sits beside the config on the host. This matters because the
// log is the only place the result of the test appears: sing-box writes to
// log.output and `docker logs sing-box` is empty, so any conclusion drawn from
// the container's stdout is worthless.
func (c *LiveConfig) HostLogPath() (string, error) {
	if c.LogOutput == "" {
		return "", fmt.Errorf("%s sets no log.output, so sing-box logs to stdout and the detection cannot be read back from a file", c.Path)
	}
	candidate := filepath.Join(filepath.Dir(c.Path), filepath.Base(c.LogOutput))
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("expected the log beside the config at %s but it is not there (%v); pass the host path explicitly", candidate, err)
	}
	return candidate, nil
}

// decodeListable handles the fork's listable fields, which marshal as a bare
// string when they hold one element and as an array otherwise.
func decodeListable(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// MentionsTag reports whether the config file still names the given tag. Used
// after cleanup, where the question is about the file's text rather than its
// structure — the tag must be gone from the whole document, including any place
// the parser above does not look.
func MentionsTag(path, tag string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return strings.Contains(string(data), tag), nil
}
