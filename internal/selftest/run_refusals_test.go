package selftest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLive(t *testing.T, doc string) Options {
	t.Helper()
	dir := t.TempDir()
	opts := DefaultOptions()
	opts.ConfigPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(opts.ConfigPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

func TestRunStopsBeforeTouchingAnythingWhenItCannotPlanTheTest(t *testing.T) {
	const api = `"experimental":{"clash_api":{"external_controller":"127.0.0.1:1","secret":"s"}}`
	cases := map[string]struct {
		doc    string
		tweak  func(*Options)
		wanted string
	}{
		"every automatic subnet is taken": {
			doc:    `{"log":{"output":"/x/l.log"},` + api + `,"endpoints":[{"tag":"p","listen_port":1,"address":"10.0.0.0/8"}]}`,
			wanted: "no free automatic self-test subnet",
		},
		"no log output to read back": {
			doc:    `{"log":{},` + api + `}`,
			wanted: "sets no log.output",
		},
		"an earlier run left its endpoint behind": {
			doc: `{"log":{"output":"/x/l.log"},` + api + `,"endpoints":[{"tag":"bt-selftest-in","listen_port":10899}]}`,
			tweak: func(o *Options) {
				o.LogPath = "/tmp/anything"
			},
			wanted: "previous run did not clean up",
		},
	}
	for name, tc := range cases {
		opts := writeLive(t, tc.doc)
		if tc.tweak != nil {
			tc.tweak(&opts)
		}
		_, err := Run(context.Background(), &bytes.Buffer{}, opts)
		if err == nil || !strings.Contains(err.Error(), tc.wanted) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAnUnreadableLiveConfigNamesTheRootRequirement(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	opts := writeLive(t, `{}`)
	if err := os.Chmod(opts.ConfigPath, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLiveConfig(opts.ConfigPath); err == nil || !strings.Contains(err.Error(), "run the self-test as root") {
		t.Errorf("error = %v", err)
	}
}

func TestListableFieldsMayBeEmptyOrMalformed(t *testing.T) {
	if got := decodeListable(nil); got != nil {
		t.Errorf("empty = %v", got)
	}
	if got := decodeListable([]byte(`42`)); got != nil {
		t.Errorf("a number = %v", got)
	}
	if got := decodeListable([]byte(`["a","b"]`)); len(got) != 2 {
		t.Errorf("array = %v", got)
	}
}
