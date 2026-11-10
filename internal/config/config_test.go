package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// vlessOptions is a config whose inbound carries protocol-specific options:
// the case the context-aware (un)marshalling exists for.
func vlessOptions() option.Options {
	return option.Options{
		Log: &option.LogOptions{Level: "warn"},
		Inbounds: []option.Inbound{{
			Type: C.TypeVLESS,
			Tag:  "vless-in",
			Options: &option.VLESSInboundOptions{
				ListenOptions: option.ListenOptions{ListenPort: 443},
				Users: []option.VLESSUser{
					{Name: "alice", UUID: "11111111-1111-1111-1111-111111111111"},
					{Name: "bob", UUID: "22222222-2222-2222-2222-222222222222"},
				},
			},
		}},
		Route: &option.RouteOptions{Final: "direct"},
	}
}

func TestMarshalEmitsIndentedJSONWithProtocolFields(t *testing.T) {
	data, err := Marshal(context.Background(), vlessOptions())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasSuffix(text, "}\n") {
		t.Fatalf("output must end with a closing brace and a newline: %q", text[max(0, len(text)-10):])
	}
	if !strings.Contains(text, "\n  \"inbounds\"") {
		t.Fatalf("output is not indented with two spaces:\n%s", text)
	}
	// Plain encoding/json would drop everything below "type" and "tag".
	for _, want := range []string{`"listen_port": 443`, `"name": "alice"`, `"uuid": "22222222-2222-2222-2222-222222222222"`} {
		if !strings.Contains(text, want) {
			t.Errorf("protocol field %s is missing from:\n%s", want, text)
		}
	}
}

func TestUnmarshalRecoversTheTypedOptionsMarshalWrote(t *testing.T) {
	data, err := Marshal(context.Background(), vlessOptions())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(got.Inbounds))
	}
	in := got.Inbounds[0]
	if in.Type != C.TypeVLESS || in.Tag != "vless-in" {
		t.Fatalf("inbound identity lost: %q %q", in.Type, in.Tag)
	}
	opts, ok := in.Options.(*option.VLESSInboundOptions)
	if !ok {
		t.Fatalf("inbound options decoded as %T, want *option.VLESSInboundOptions", in.Options)
	}
	if opts.ListenPort != 443 {
		t.Errorf("listen_port = %d, want 443", opts.ListenPort)
	}
	if len(opts.Users) != 2 || opts.Users[0].Name != "alice" || opts.Users[1].UUID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("users did not round-trip: %+v", opts.Users)
	}
	if got.Route == nil || got.Route.Final != "direct" {
		t.Errorf("route lost: %+v", got.Route)
	}

	// A second pass must be byte-identical: Marshal is what migrations compare.
	again, err := Marshal(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(data) {
		t.Fatalf("marshal is not stable across a round trip:\n--- first\n%s\n--- second\n%s", data, again)
	}
}

func TestUnmarshalRejectsMalformedConfig(t *testing.T) {
	for name, input := range map[string]string{
		"not json":      "inbounds:\n  - x",
		"truncated":     `{"inbounds": [`,
		"unknown field": `{"definitely_not_a_field": 1}`,
		"unknown type":  `{"inbounds":[{"type":"no-such-protocol","tag":"x"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Unmarshal(context.Background(), []byte(input)); err == nil {
				t.Fatalf("expected an error for %q", input)
			} else if !strings.HasPrefix(err.Error(), "parse config: ") {
				t.Fatalf("error should be wrapped as a parse failure: %v", err)
			}
		})
	}
}

func TestWriteCreatesFileWithContentAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Write(path, []byte("hello\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("content = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640 (umask must not narrow what the caller asked for)", info.Mode().Perm())
	}
}

func TestWriteReplacesAnExistingFileAndLeavesNoTemporaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("old contents that are longer than the new ones"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Fatalf("content = %q, want a clean replacement without remnants of the old file", got)
	}
	// The replacement takes the new permissions too: it is a different inode.
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory should hold only the config, found %v", names)
	}
}

func TestWriteIntoAMissingDirectoryFailsCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "config.json")
	err := Write(path, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected an error when the directory does not exist")
	}
	if !strings.Contains(err.Error(), "create temporary file") {
		t.Fatalf("error does not say what failed: %v", err)
	}
}

func TestWriteFailureKeepsTheOriginalAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	// The destination is a non-empty directory: rename onto it must fail, and the
	// failed attempt must not leave its temporary file behind.
	path := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Write(path, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected the rename to fail")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Fatalf("error should name the rename: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("a temporary file leaked: %v", entries)
	}
}
