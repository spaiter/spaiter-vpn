package config

import (
	"context"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/core/option"
)

// An inbound with a type but no options cannot be rendered. That must be an
// error naming the stage, never an empty or partial file.
func TestMarshalRefusesAnInboundWithoutOptions(t *testing.T) {
	options := option.Options{Inbounds: []option.Inbound{{Type: "vless", Tag: "in"}}}
	data, err := Marshal(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "marshal config") {
		t.Fatalf("err = %v", err)
	}
	if len(data) != 0 {
		t.Errorf("a failed marshal returned %d bytes", len(data))
	}
}
