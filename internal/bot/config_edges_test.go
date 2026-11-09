package bot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVKReloginPathsLiveUnderTheDataDirectory(t *testing.T) {
	p := Paths{DataDir: "/data"}
	if p.VKReloginDir() != "/data/vk-relogin" || p.VKReloginStatus() != "/data/vk-relogin/status" || p.VKReloginCode() != "/data/vk-relogin/code" {
		t.Errorf("paths = %q %q %q", p.VKReloginDir(), p.VKReloginStatus(), p.VKReloginCode())
	}
}

func TestDurationsAreStringsInJSONAndRefuseGarbage(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"90s"`), &d); err != nil || d.Build() != 90*time.Second {
		t.Errorf("90s = %v, %v", d.Build(), err)
	}
	if err := json.Unmarshal([]byte(`"soon"`), &d); err == nil || !strings.Contains(err.Error(), "bad duration") {
		t.Errorf("garbage: %v", err)
	}
	if err := json.Unmarshal([]byte(`90`), &d); err == nil {
		t.Error("a bare number was accepted as a duration")
	}
	out, err := json.Marshal(Duration(2 * time.Minute))
	if err != nil || string(out) != `"2m0s"` {
		t.Errorf("marshal = %s, %v", out, err)
	}
}

func TestLoadTreatsNoPathAndMissingFilesAsTheDefaults(t *testing.T) {
	want := Defaults()
	if got, err := Load(""); err != nil || got.Subscription.Port != want.Subscription.Port {
		t.Errorf("no path: %v", err)
	}
	if got, err := Load(filepath.Join(t.TempDir(), "absent.json")); err != nil || got.Subscription.Port != want.Subscription.Port {
		t.Errorf("missing file: %v", err)
	}
	// A directory cannot be read as a file, which is an error and not a default.
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("directory: %v", err)
	}
}

func TestValidateNamesEachIntervalThatMustBePositive(t *testing.T) {
	for name, mutate := range map[string]func(c *Config){
		"sub_refresh": func(c *Config) { c.Intervals.SubRefresh = 0 },
		"hash_check":  func(c *Config) { c.Intervals.HashCheck = 0 },
		"notify_poll": func(c *Config) { c.Intervals.NotifyPoll = 0 },
	} {
		c := ExampleConfig()
		mutate(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "intervals."+name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMarshalRoundTripsThroughLoad(t *testing.T) {
	c := ExampleConfig()
	data, err := c.Marshal()
	if err != nil || !strings.HasSuffix(string(data), "}\n") {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bot.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Subscription.Port != c.Subscription.Port || loaded.Intervals.SubRefresh != c.Intervals.SubRefresh {
		t.Error("the config did not survive a round trip")
	}
}
