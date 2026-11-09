package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// Restore is a deployment carried over from a backup: the core's configuration,
// which holds every server-side key and every user the bot added, and the
// handover snapshot beside it.
type Restore struct {
	Config  []byte
	Secrets []byte
}

// renderRestored renders a first install from a backup instead of minting one.
//
// It is a migration's render, run against the backup rather than the live
// files: every credential is recovered from the backed-up configuration and the
// shape is rendered for this host — its XDP interface, and whatever the desired
// state says now. Users the bot provisioned keep exactly what they held and are
// issued nothing, because the bot minted their accounts and stores the private
// halves a credential minted here would lack. Nothing already issued changes,
// so no client needs a new key; at most the address they dial.
func (o Options) renderRestored(ctx context.Context, spec profile.Spec) (*profile.Rendered, error) {
	restored, err := parseRuntimeState(ctx, o.Restore.Config, o.Restore.Secrets)
	if err != nil {
		return nil, fmt.Errorf("read the backup: %w", err)
	}
	spec.Users = restored.credentials.Names()
	spec.Mint = map[string]map[string]bool{}
	for _, name := range spec.Users {
		if !slices.Contains(o.Desired.Bootstrap.SeedUsers, name) {
			spec.Mint[name] = map[string]bool{}
		}
	}
	bundle, err := profile.Regenerate(spec, restored.credentials)
	if err != nil {
		return nil, fmt.Errorf("render the backed-up deployment for this host: %w", err)
	}
	handover, err := refreshHandover(restored.handover, bundle.Secrets)
	if err != nil {
		return nil, err
	}
	secretsJSON, err := json.MarshalIndent(handover, "", "  ")
	if err != nil {
		return nil, err
	}
	secretsJSON = append(secretsJSON, '\n')
	configJSON, err := config.Marshal(ctx, bundle.Options)
	if err != nil {
		return nil, err
	}
	if err := o.CheckConfig(ctx, configJSON); err != nil {
		return nil, fmt.Errorf("the restored configuration is not usable: %w", err)
	}
	fmt.Fprintf(o.Out, "restored configuration: validated, %d users carried over from the backup\n", restored.users)
	return &profile.Rendered{Bundle: bundle, ConfigJSON: configJSON, SecretsJSON: secretsJSON}, nil
}
