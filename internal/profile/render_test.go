package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestRenderProducesOneConsistentBundle(t *testing.T) {
	spec := Defaults([]string{"alice"})
	rendered, err := Render(context.Background(), spec)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if rendered.Bundle == nil {
		t.Fatal("Render returned no typed bundle")
	}
	if len(rendered.ConfigJSON) == 0 || !json.Valid(rendered.ConfigJSON) {
		t.Fatal("config output is not valid JSON")
	}
	if len(rendered.SecretsJSON) == 0 || !json.Valid(rendered.SecretsJSON) {
		t.Fatal("secrets output is not valid JSON")
	}
	if !bytes.HasSuffix(rendered.ConfigJSON, []byte("\n")) || !bytes.HasSuffix(rendered.SecretsJSON, []byte("\n")) {
		t.Fatal("rendered JSON files must end with a newline")
	}

	var secrets Secrets
	if err := json.Unmarshal(rendered.SecretsJSON, &secrets); err != nil {
		t.Fatalf("decode rendered secrets: %v", err)
	}
	if secrets.ClashAPISecret == "" || secrets.ClashAPISecret != rendered.Bundle.Secrets.ClashAPISecret {
		t.Fatal("serialized secrets were not derived from the returned bundle")
	}
}
