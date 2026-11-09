package profile

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spaiter/spaiter-vpn/internal/config"
)

// Rendered is one generated profile together with the exact JSON files that
// represent it on disk. Keeping the typed bundle and both serialisations in a
// single result prevents callers from independently generating credentials for
// config.json and secrets.json.
type Rendered struct {
	Bundle      *Bundle
	ConfigJSON  []byte
	SecretsJSON []byte
}

// Render generates a profile once and serialises both halves of it. It does no
// filesystem or host mutation, so init and bootstrap can use the same API and
// choose their own write/transaction policy.
func Render(ctx context.Context, spec Spec) (*Rendered, error) {
	bundle, err := Generate(spec)
	if err != nil {
		return nil, err
	}
	configData, err := config.Marshal(ctx, bundle.Options)
	if err != nil {
		return nil, err
	}
	secretsData, err := json.MarshalIndent(bundle.Secrets, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal secrets: %w", err)
	}
	secretsData = append(secretsData, '\n')
	return &Rendered{
		Bundle:      bundle,
		ConfigJSON:  configData,
		SecretsJSON: secretsData,
	}, nil
}
