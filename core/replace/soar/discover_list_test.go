package soar

import "testing"

func TestDiscoveryList(t *testing.T) {
	d := Discovery{Country: "IR", Candidates: []string{"192.0.2.1"}}
	list := d.List()
	if len(list) < 10 || list[0] != "192.0.2.1:53" {
		t.Fatalf("list: %v", list[:min(len(list), 3)])
	}
	seen := map[string]bool{}
	for _, r := range list {
		if seen[r] {
			t.Fatalf("%s twice", r)
		}
		seen[r] = true
	}
	if !seen["1.1.1.1:53"] {
		t.Fatal("no global resolver")
	}
	if n := len(Discovery{Country: "IR", SampleRanges: 20}.List()); n < len(Discovery{Country: "IR"}.List())+20 {
		t.Fatalf("sampled: %d", n)
	}
}
