package service

import (
	"context"
	"encoding/json"
	"testing"
)

// With the AmneziaWG 3.1 gate open and an endpoint behind it, the bundle gains
// a second AWG node; with the gate closed it stays out even when the endpoint exists.
func TestTheAWG3GateAddsItsNodeOnlyWhenOpen(t *testing.T) {
	count := func(open bool) int {
		s, api, _, _, _ := newService(t)
		s.cfg.Bundle.EnableAWG3 = open
		stored, err := api.Endpoint(context.Background(), s.cfg.Tags.AWG)
		if err != nil {
			t.Fatal(err)
		}
		var endpoint map[string]any
		if err := json.Unmarshal(stored, &endpoint); err != nil {
			t.Fatal(err)
		}
		endpoint["tag"] = s.cfg.Tags.AWG3
		api.endpoints[s.cfg.Tags.AWG3] = endpoint

		bundle, err := s.Bundle(context.Background(), "42", true)
		if err != nil {
			t.Fatalf("Bundle: %v", err)
		}
		var parsed struct {
			Outbounds []struct{ Type string } `json:"outbounds"`
		}
		if err := json.Unmarshal(bundle, &parsed); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, o := range parsed.Outbounds {
			if o.Type == "awg" {
				n++
			}
		}
		return n
	}
	if closed, open := count(false), count(true); open != closed+1 {
		t.Errorf("awg nodes: gate closed %d, gate open %d", closed, open)
	}
}
