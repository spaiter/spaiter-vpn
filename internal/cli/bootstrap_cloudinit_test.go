package cli

import "testing"

func TestReleaseTag(t *testing.T) {
	cases := map[string]string{
		"v0.1.0+299c2118":     "v0.1.0",
		"v0.1.0":              "v0.1.0",
		"v1.2.3-rc1+abcdef12": "v1.2.3-rc1",
		"dev":                 "",
		"299c2118":            "",
		"v0.1":                "",
		"0.1.0+299c2118":      "",
		"":                    "",
	}
	for version, want := range cases {
		if got := releaseTag(version); got != want {
			t.Errorf("releaseTag(%q) = %q, want %q", version, got, want)
		}
	}
}
