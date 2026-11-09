package apply

import (
	"context"
	"strings"
	"testing"
)

func TestRunRefusesToStartWithoutWhatItProvesThingsWith(t *testing.T) {
	cases := map[string]struct {
		clear func(o *Options)
		want  string
	}{
		"discovery": {func(o *Options) { o.Discover = nil }, "discovery function"},
		"preflight": {func(o *Options) { o.Preflight = nil }, "preflight function"},
		"validator": {func(o *Options) { o.CheckConfig = nil }, "configuration validator"},
		"compose":   {func(o *Options) { o.Compose = nil }, "compose runner"},
		"self-test": {func(o *Options) { o.SelfTest = nil }, "self-test"},
	}
	for name, tc := range cases {
		h := newHarness(t)
		tc.clear(&h.options)
		if _, err := Run(context.Background(), h.options); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRunWithoutAnOutputWriterStillWorks(t *testing.T) {
	h := newHarness(t)
	h.options.Out = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
}
