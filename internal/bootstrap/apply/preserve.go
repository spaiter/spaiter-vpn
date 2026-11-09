package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// runtimeState is the live half of a deployment: config.json is the
// authoritative server-side credential store, while secrets.json is the
// original client handover snapshot and must remain byte-identical.
type runtimeState struct {
	config                []byte
	configDigest          string
	secretsDigest         string
	expectedSecretsDigest string
	credentials           profile.Secrets
	handover              profile.Secrets
	subnetChanges         []transaction.Change
	// rotated names the users whose credentials this apply reissued on purpose.
	rotated []string
	// users is how many live user records config.json holds, including users the
	// bot added after the initial handover snapshot was written.
	users int
}

// readRuntimeState loads what a convergence must not change and what a
// migration must carry into the newly rendered shape.
func (o Options) readRuntimeState(ctx context.Context) (*runtimeState, error) {
	configData, err := os.ReadFile(o.Layout.ConfigPath())
	if err != nil {
		return nil, fmt.Errorf("read the live configuration: %w", err)
	}
	secrets, err := os.ReadFile(o.Layout.SecretsPath())
	if err != nil {
		return nil, fmt.Errorf("read the live credentials: %w", err)
	}
	return parseRuntimeState(ctx, configData, secrets)
}

// parseRuntimeState reads a configuration and its handover, from this host or
// from a backup being restored.
func parseRuntimeState(ctx context.Context, configData, secrets []byte) (*runtimeState, error) {
	state := &runtimeState{
		config:        configData,
		configDigest:  digestOf(configData),
		secretsDigest: digestOf(secrets),
	}
	if err := json.Unmarshal(secrets, &state.handover); err != nil {
		return nil, fmt.Errorf("parse the client credentials: %w", err)
	}

	parsed, err := config.Unmarshal(ctx, configData)
	if err != nil {
		return nil, fmt.Errorf("parse the live configuration: %w", err)
	}
	state.credentials, err = profile.SecretsFromConfig(parsed)
	if err != nil {
		return nil, fmt.Errorf("recover credentials from the live configuration: %w", err)
	}
	state.users = len(state.credentials.Users)
	if state.users == 0 {
		return nil, fmt.Errorf("the live configuration lists no users; refusing to converge a deployment whose credential store cannot be read")
	}
	return state, nil
}

// verifyPreserved checks that convergence or migration left client handover
// credentials alone.
//
// rewroteConfig says this apply replaced config.json on purpose, which only a
// migration does.
//
// secrets.json is held to byte equality: nothing in a running deployment ever
// writes it, so any change is this apply's fault.
//
// config.json deliberately is NOT. The core owns that file and rewrites it
// through config_output_path whenever a user or peer is provisioned — and the
// self-test this apply just ran adds a throwaway endpoint and removes it again,
// so a digest comparison across an apply would fail on a deployment that is
// behaving correctly. What protects it instead is structural: it is not in the
// transaction at all, and the receipt records it as runtime-mutable so no
// future apply will replace it either. A changed digest here is reported as
// information, not as a failure.
func (o Options) verifyPreserved(before *runtimeState, mode plan.Mode) error {
	secrets, err := os.ReadFile(o.Layout.SecretsPath())
	if err != nil {
		return fmt.Errorf("re-read the live credentials: %w", err)
	}
	wantSecrets := before.secretsDigest
	if before.expectedSecretsDigest != "" {
		wantSecrets = before.expectedSecretsDigest
	}
	if digestOf(secrets) != wantSecrets {
		return fmt.Errorf("the client credentials at %s changed during this apply; every existing client would stop working", o.Layout.SecretsPath())
	}

	config, err := os.ReadFile(o.Layout.ConfigPath())
	if err != nil {
		return fmt.Errorf("re-read the live configuration: %w", err)
	}
	// Who rewrote the config decides what this line may claim. A convergence
	// never writes it, so a changed digest there is the core recording a live
	// change; a migration writes it deliberately, and reporting that as the
	// core's doing would be a false statement about the apply that just ran.
	switch {
	case len(before.rotated) > 0:
		fmt.Fprintf(o.Out, "rotated: %s now hold new credentials; their old client configurations no longer connect, and %d other live users kept theirs\n",
			strings.Join(before.rotated, ", "), before.users-len(before.rotated))
	case mode == plan.ModeMigrate || mode == plan.ModeRestartMigrate || mode == plan.ModeSubnetMigrate:
		fmt.Fprintf(o.Out, "migrated: %s re-rendered for the requested shape, %d live users carried over with their existing credentials\n",
			o.Layout.ConfigPath(), before.users)
	case digestOf(config) != before.configDigest:
		fmt.Fprintf(o.Out, "note: the core rewrote %s during this apply, which is how it records live changes; the credentials are byte-identical\n", o.Layout.ConfigPath())
		fallthrough
	default:
		fmt.Fprintf(o.Out, "preserved: %d client credential sets unchanged\n", before.users)
	}
	return nil
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
