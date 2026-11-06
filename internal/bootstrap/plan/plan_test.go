package plan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestGoldenPlans(t *testing.T) {
	base := state.Default([]string{"owner"})

	botMissing := state.Default([]string{"owner"})
	botMissing.Bot.Enabled = true
	botMissing.Bot.AdminIDs = []int64{123456789}
	botMissing.Bot.PublicHost = "vpn.example.com"
	botMissing.Bot.TelegramToken = "telegram-token"
	botMissing.Bootstrap.InstallDocker = false
	botMissingObserved := readyObservation(t, botMissing)
	botMissingObserved.Docker = discover.Docker{}
	botMissingObserved.Credentials["telegram-token"] = discover.File{Status: discover.FileAbsent}

	previous := state.Default([]string{"owner"})
	reconcile := state.Default([]string{"owner"})
	reconcile.Deployment.Image = "registry.example/spaiter-vpn-core:next"
	reconcileObserved := readyObservation(t, reconcile)
	setExisting(t, &reconcileObserved, previous)
	setRuntimeComplete(&reconcileObserved)
	reconcileObserved.Logrotate = regularFile()

	migration := state.Default([]string{"owner"})
	migration.Deployment.Ports[profile.AWG2]++
	migrationObserved := readyObservation(t, migration)
	setExisting(t, &migrationObserved, previous)
	setRuntimeComplete(&migrationObserved)
	migrationObserved.Logrotate = regularFile()

	tests := []struct {
		name     string
		desired  state.State
		observed discover.Observed
	}{
		{"fresh-ready", base, readyObservation(t, base)},
		{"fresh-blocked", botMissing, botMissingObserved},
		{"reconcile-image", reconcile, reconcileObserved},
		{"migration-port", migration, migrationObserved},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, err := Build(test.desired, test.observed)
			if err != nil {
				t.Fatal(err)
			}
			second, err := Build(test.desired, test.observed)
			if err != nil {
				t.Fatal(err)
			}
			firstJSON, err := first.MarshalIndent()
			if err != nil {
				t.Fatal(err)
			}
			secondJSON, err := second.MarshalIndent()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstJSON, secondJSON) {
				t.Fatal("identical inputs produced different plans")
			}

			actualGolden := renderGolden(t, first)
			path := filepath.Join("testdata", test.name+".golden")
			// UPDATE_GOLDEN=1 rewrites the file; review the diff before committing.
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(path, actualGolden, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			golden, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v\nactual plan:\n%s", path, err, actualGolden)
			}
			if !bytes.Equal(actualGolden, golden) {
				t.Fatalf("plan differs from %s\nactual:\n%s\nexpected:\n%s", path, actualGolden, golden)
			}
		})
	}
}

func TestMissingRequiredFirewallRuleIsPlanned(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	missing := observed.Firewall.Required[0]
	delete(observed.Firewall.Rules, missing)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range built.Actions {
		if action.ID == "firewall" {
			if action.Disposition != Apply || !action.Mutates || !bytes.Contains([]byte(action.Summary), []byte(missing)) {
				t.Fatalf("firewall action does not add missing required rule %s: %#v", missing, action)
			}
			return
		}
	}
	t.Fatal("plan has no firewall action")
}

func TestSupportedMigrationPlansTheLiveApply(t *testing.T) {
	previous := state.Default([]string{"owner"})
	desired := state.Default([]string{"owner"})
	desired.Deployment.Ports[profile.AWG2]++
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeMigrate || built.Blocked {
		t.Fatalf("supported migration was not planned: %#v", built)
	}
	seen := map[string]bool{}
	for _, action := range built.Actions {
		seen[action.ID] = true
	}
	if !seen["stage-migration"] || !seen["management-apply"] {
		t.Fatalf("migration lacks its render/apply actions: %#v", built.Actions)
	}
}

func TestRestartMigrationPlansAForcedRecreate(t *testing.T) {
	previous := state.Default([]string{"owner"})
	desired := state.Default([]string{"owner"})
	desired.Deployment.LogLevel = "trace"
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeRestartMigrate || built.Blocked {
		t.Fatalf("restart migration was not planned: %#v", built)
	}
	seen := map[string]bool{}
	for _, action := range built.Actions {
		seen[action.ID] = true
	}
	if !seen["stage-restart-migration"] || !seen["compose-recreate"] {
		t.Fatalf("restart migration lacks its render/recreate actions: %#v", built.Actions)
	}
	if seen["management-apply"] || seen["compose-up"] {
		t.Fatalf("restart migration also planned an incompatible live/up action: %#v", built.Actions)
	}
}

func TestRestartMigrationAbsorbsLiveCompatibleChanges(t *testing.T) {
	previous := state.Default([]string{"owner"})
	desired := state.Default([]string{"owner"})
	desired.Deployment.LogLevel = "trace"
	desired.Deployment.Ports = maps.Clone(desired.Deployment.Ports)
	desired.Deployment.Ports[profile.AWG2]++
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeRestartMigrate || built.Blocked {
		t.Fatalf("mixed live/restart migration mode = %q blocked=%t", built.Mode, built.Blocked)
	}
}

func TestInterruptedRestartPlansRecoveryRecreate(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	setExisting(t, &observed, desired)
	setRuntimeComplete(&observed)
	observed.Runtime.RecreatePending = true
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeRestartRecover || built.Blocked {
		t.Fatalf("restart recovery was not planned: %#v", built)
	}
	seen := map[string]bool{}
	for _, action := range built.Actions {
		seen[action.ID] = true
	}
	if !seen["compose-recreate"] || seen["management-sync"] || seen["stage-restart-migration"] {
		t.Fatalf("restart recovery has the wrong actions: %#v", built.Actions)
	}
}

func TestUnsupportedMigrationPlanContainsNoMutatingActions(t *testing.T) {
	previous := state.Default([]string{"owner"})
	desired := state.Default([]string{"owner"})
	desired.Deployment.Subnets = maps.Clone(desired.Deployment.Subnets)
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeMigrationRequired || !built.Blocked {
		t.Fatalf("unsafe migration boundary lost: %#v", built)
	}
	for _, action := range built.Actions {
		if action.Mutates {
			t.Fatalf("blocked migration proposes mutation: %#v", action)
		}
	}
}

func TestExactPreserveHostPolicyPlansSubnetMigration(t *testing.T) {
	previous := state.Default([]string{"owner"})
	desired := state.Default([]string{"owner"})
	desired.Deployment.Subnets = maps.Clone(desired.Deployment.Subnets)
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.AWG2: {From: previous.Deployment.Subnets[profile.AWG2], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeSubnetMigrate || built.Blocked {
		t.Fatalf("exact subnet policy was not accepted: %#v", built)
	}
	seen := map[string]bool{}
	for _, action := range built.Actions {
		seen[action.ID] = true
	}
	if !seen["stage-subnet-migration"] || !seen["compose-recreate"] {
		t.Fatalf("subnet migration has the wrong actions: %#v", built.Actions)
	}
}

func TestSubnetMigrationPlansBotCredentialTransaction(t *testing.T) {
	previous := state.Default([]string{"owner"})
	previous.Bot.Enabled = true
	previous.Bot.AdminIDs = []int64{1}
	previous.Bot.PublicHost = "vpn.example.com"
	previous.Bot.TelegramToken = "telegram-token"
	desired := previous
	desired.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.AWG2: {From: previous.Deployment.Subnets[profile.AWG2], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeSubnetMigrate || built.Blocked {
		t.Fatalf("bot-backed migration was not planned: %#v", built)
	}
}

func TestExactPreserveExistingPolicyPlansSeedUserMigration(t *testing.T) {
	previous := state.Default([]string{"owner", "guest"})
	unauthorised := state.Default([]string{"owner", "newcomer"})
	observed := readyObservation(t, unauthorised)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	blockedPlan, err := Build(unauthorised, observed)
	if err != nil {
		t.Fatal(err)
	}
	if blockedPlan.Mode != ModeMigrationRequired || !blockedPlan.Blocked {
		t.Fatalf("unauthorised seedUsers change was not blocked: %#v", blockedPlan)
	}

	desired := unauthorised
	desired.MigrationPolicy = &state.MigrationPolicy{
		SeedUsers: &state.SeedUsersMigration{
			From:     []string{"owner", "guest"},
			To:       []string{"owner", "newcomer"},
			Strategy: state.SeedUsersStrategyPreserveExisting,
		},
	}
	observed = readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	built, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if built.Mode != ModeMigrate || built.Blocked {
		t.Fatalf("exact seedUsers policy was not planned as migrate: %#v", built)
	}

	// Retaining the applied policy in desired.json must not block a subsequent
	// live port migration.
	followUp := desired
	followUp.Deployment.Ports = maps.Clone(desired.Deployment.Ports)
	followUp.Deployment.Ports[profile.AWG2]++
	followUpObserved := readyObservation(t, followUp)
	setExisting(t, &followUpObserved, desired)
	setRuntimeComplete(&followUpObserved)
	followUpPlan, err := Build(followUp, followUpObserved)
	if err != nil {
		t.Fatal(err)
	}
	if followUpPlan.Mode != ModeMigrate || followUpPlan.Blocked {
		t.Fatalf("retained seedUsers audit policy blocked follow-up migration: %#v", followUpPlan)
	}
}

func renderGolden(t *testing.T, value Plan) []byte {
	t.Helper()
	var output bytes.Buffer
	fmt.Fprintf(&output, "apiVersion: %s\n", value.APIVersion)
	fmt.Fprintf(&output, "desiredDigest: %s\n", value.DesiredDigest)
	fmt.Fprintf(&output, "observationDigest: %s\n", value.ObservationDigest)
	fmt.Fprintf(&output, "mode: %s\nblocked: %t\n", value.Mode, value.Blocked)
	output.WriteString("changes:\n")
	for _, change := range value.Changes {
		before, err := json.Marshal(change.Before)
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(change.After)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&output, "- %s | %s | %s -> %s\n", change.Path, change.Class, before, after)
	}
	output.WriteString("actions:\n")
	for _, action := range value.Actions {
		fmt.Fprintf(&output, "- %s | %s | mutates=%t | %s\n", action.ID, action.Disposition, action.Mutates, action.Summary)
	}
	return output.Bytes()
}

func readyObservation(t *testing.T, desired state.State) discover.Observed {
	t.Helper()
	spec, err := desired.PreflightSpec([]string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]string{}
	required := []string{}
	for _, rule := range firewall.Rules(spec) {
		rules[rule.String()] = "allowed"
		required = append(required, rule.String())
	}
	var botUser *discover.SystemUser
	if desired.Bot.Enabled && desired.Bot.DedicatedUser {
		botUser = &discover.SystemUser{Name: "spaiter-vpn-bot", Exists: true, UID: 998, GID: 998}
	}
	return discover.Observed{
		BotUser:          botUser,
		APIVersion:       discover.ObservationVersion,
		Platform:         discover.Platform{OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "24.04", Systemd: true},
		Privileges:       discover.Privileges{EUID: 1000},
		Docker:           discover.Docker{CLIAvailable: true, DaemonReachable: true, ComposeAvailable: true, ServerVersion: "27.5.1"},
		Network:          discover.Network{DefaultInterface: "eth0"},
		Firewall:         discover.Firewall{Kind: "ufw", Active: true, Readable: true, Required: required, Rules: rules, Detail: "fixture"},
		ExistingDesired:  discover.ExistingDesired{Status: discover.FileAbsent},
		Runtime:          discover.Runtime{Config: absentFile(), Secrets: absentFile(), Compose: absentFile(), Receipt: absentFile()},
		Credentials:      map[state.SecretRef]discover.File{},
		CertificateFiles: map[string]discover.File{},
		Logrotate:        absentFile(),
	}
}

func setExisting(t *testing.T, observed *discover.Observed, existing state.State) {
	t.Helper()
	digest, err := existing.Digest()
	if err != nil {
		t.Fatal(err)
	}
	observed.ExistingDesired = discover.ExistingDesired{Status: discover.FileRegular, Digest: digest, State: &existing}
}

func setRuntimeComplete(observed *discover.Observed) {
	observed.Runtime = discover.Runtime{Config: regularFile(), Secrets: regularFile(), Compose: regularFile(), Receipt: regularFile()}
}

func absentFile() discover.File { return discover.File{Status: discover.FileAbsent} }
func regularFile() discover.File {
	return discover.File{Status: discover.FileRegular, Mode: 0o600, UID: 0}
}
