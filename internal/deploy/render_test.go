package deploy

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestRenderReturnsTheExistingRendererOutputs(t *testing.T) {
	params := botParams()
	artifacts, err := Render(params)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	wantBot, err := params.Bot.ConfigJSON(params)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		artifact *Artifact
		name     string
		data     []byte
		mode     uint32
	}{
		{&artifacts.Compose, ComposeFileName, []byte(params.Compose()), 0o644},
		{&artifacts.Environment, EnvFileName, []byte(params.Env()), 0o644},
		{&artifacts.Logrotate, LogrotateFileName, []byte(params.Logrotate()), 0o644},
		{artifacts.ReloadAgent, ReloadAgentScriptName, []byte(params.Reload.Script()), 0o755},
		{artifacts.BotConfig, BotConfigFileName, wantBot, 0o644},
	}
	for _, check := range checks {
		if check.artifact == nil {
			t.Fatalf("artifact %s is absent", check.name)
		}
		if check.artifact.Name != check.name || !bytes.Equal(check.artifact.Data, check.data) || uint32(check.artifact.Mode) != check.mode {
			t.Errorf("artifact %s differs from its existing renderer", check.name)
		}
	}
	wantOrder := []string{ComposeFileName, EnvFileName, LogrotateFileName, ReloadAgentScriptName, BotConfigFileName}
	var gotOrder []string
	for _, file := range artifacts.Files() {
		gotOrder = append(gotOrder, file.Name)
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("file order = %v, want %v", gotOrder, wantOrder)
	}
}

func TestRenderOmitsOptionalArtifacts(t *testing.T) {
	artifacts, err := Render(Params{Image: "example/core:sha", ConfigDir: "/config", CacheDir: "/cache"})
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.ReloadAgent != nil || artifacts.BotConfig != nil {
		t.Fatal("disabled optional services produced artifacts")
	}
	if len(artifacts.Files()) != 3 {
		t.Fatalf("got %d files, want 3", len(artifacts.Files()))
	}
}

// The bot's files share the core's directory, so the core must name its one
// config file: a directory load merges bot.json too and refuses to start.
func TestCoreLoadsOnlyItsOwnConfig(t *testing.T) {
	compose := botParams().Compose()
	if !strings.Contains(compose, "-c /etc/sing-box/config.json run") || strings.Contains(compose, " -C ") {
		t.Fatalf("the core does not load exactly config.json:\n%s", compose)
	}
}
