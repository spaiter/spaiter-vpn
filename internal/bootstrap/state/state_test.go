package state

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestDefaultRoundTripIsStrictAndStable(t *testing.T) {
	want := Default([]string{"alice", "bob"})
	data, err := want.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := want.Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := got.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatalf("digest changed across round trip: %s != %s", gotDigest, wantDigest)
	}
	if len(got.Deployment.Ports) != len(profile.AllProtocols) {
		t.Fatalf("defaults are not complete: got %d ports for %d protocols", len(got.Deployment.Ports), len(profile.AllProtocols))
	}
}

func TestDecodeRejectsUnknownMissingVersionAndTrailingJSON(t *testing.T) {
	valid, err := Default([]string{"alice"}).MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"unknown field":   bytes.Replace(valid, []byte(`"deployment": {`), []byte(`"unknown": true, "deployment": {`), 1),
		"missing version": bytes.Replace(valid, []byte(`"apiVersion": "spaiter-vpn/v1alpha1",`), nil, 1),
		"missing false":   bytes.Replace(valid, []byte("    \"installDocker\": false,\n"), nil, 1),
		"future version":  bytes.Replace(valid, []byte(APIVersionV1Alpha1), []byte("spaiter-vpn/v9"), 1),
		"trailing value":  append(append([]byte(nil), valid...), []byte("{}")...),
		"duplicate field": bytes.Replace(valid, []byte(`"tier": "a",`), []byte(`"tier": "a", "tier": "a",`), 1),
		"null array":      bytes.Replace(valid, []byte(`"adminIds": []`), []byte(`"adminIds": null`), 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("Parse accepted invalid desired state")
			}
		})
	}

	future := bytes.Replace(valid, []byte(APIVersionV1Alpha1), []byte("spaiter-vpn/v9"), 1)
	if _, err := Parse(future); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("future version was not rejected by version dispatch: %v", err)
	}
}

func TestCanonicalNormalisesSetsButNotSeedUserOrder(t *testing.T) {
	a := Default([]string{"alice", "bob"})
	b := Default([]string{"alice", "bob"})
	a.Bot.AdminIDs = []int64{20, 10}
	b.Bot.AdminIDs = []int64{10, 20}
	a.Bot.Enabled, b.Bot.Enabled = true, true
	a.Bot.TelegramToken, b.Bot.TelegramToken = "telegram-token", "telegram-token"
	a.Bot.PublicHost, b.Bot.PublicHost = "vpn.example.com", "vpn.example.com"

	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatal("set ordering changed the digest")
	}

	b.Bootstrap.SeedUsers = []string{"bob", "alice"}
	db, err = b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da == db {
		t.Fatal("seed-user order did not change the digest")
	}
}

func TestValidationRejectsUnsafeOrIncompleteState(t *testing.T) {
	tests := map[string]func(*State){
		"moving image":              func(s *State) { s.Deployment.Image = "example/core:latest" },
		"missing port":              func(s *State) { delete(s.Deployment.Ports, profile.AWG2) },
		"unknown disabled protocol": func(s *State) { s.Deployment.Protocols.Disabled = []profile.Protocol{"nope"} },
		"bot without administrator": func(s *State) { s.Bot.Enabled = true; s.Bot.TelegramToken = "telegram-token" },
		"credential path":           func(s *State) { s.Bot.Enabled = true; s.Bot.AdminIDs = []int64{1}; s.Bot.TelegramToken = "../token" },
		"auto mixed with interface": func(s *State) { s.Deployment.XDPInterfaces = []string{"auto", "eth0"} },
		"relative WDTT config": func(s *State) {
			s.Bot.Enabled = true
			s.Bot.AdminIDs = []int64{1}
			s.Bot.PublicHost = "vpn.example.com"
			s.Bot.TelegramToken = "telegram-token"
			s.Bot.WDTTConfigDirectory = "relay"
		},
		"CDN host with a scheme": func(s *State) {
			s.Bot.Enabled = true
			s.Bot.PublicHost = "vpn.example.com"
			s.Bot.TelegramToken = "telegram-token"
			s.Bot.CDNHost = "https://cdn.example.com"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			state := Default([]string{"alice"})
			mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("Validate accepted invalid state")
			}
		})
	}
}

func TestSubnetMigrationPolicyIsExactAndOptional(t *testing.T) {
	s := Default([]string{"alice"})
	data, err := s.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("migrationPolicy")) {
		t.Fatal("default state unexpectedly contains a migration policy")
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("legacy policy-free state no longer parses: %v", err)
	}

	s.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	s.MigrationPolicy = &MigrationPolicy{Subnets: map[profile.Protocol]SubnetMigration{
		profile.AWG2: {From: "10.10.0.0/24", To: "10.99.0.0/24", Strategy: SubnetStrategyPreserveHost},
	}}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid subnet policy rejected: %v", err)
	}

	tests := map[string]func(*State){
		"unknown strategy": func(s *State) {
			migration := s.MigrationPolicy.Subnets[profile.AWG2]
			migration.Strategy = "compact"
			s.MigrationPolicy.Subnets[profile.AWG2] = migration
		},
		"wrong target": func(s *State) {
			migration := s.MigrationPolicy.Subnets[profile.AWG2]
			migration.To = "10.98.0.0/24"
			s.MigrationPolicy.Subnets[profile.AWG2] = migration
		},
		"non-canonical source": func(s *State) {
			migration := s.MigrationPolicy.Subnets[profile.AWG2]
			migration.From = "10.10.0.1/24"
			s.MigrationPolicy.Subnets[profile.AWG2] = migration
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := s
			candidate.MigrationPolicy = &MigrationPolicy{Subnets: cloneMap(s.MigrationPolicy.Subnets)}
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate accepted an unsafe subnet policy")
			}
		})
	}
}

func TestSeedUsersMigrationPolicyAndRetainedAuditRecords(t *testing.T) {
	previous := Default([]string{"alice", "bob"})
	desired := Default([]string{"alice", "carol"})
	desired.MigrationPolicy = &MigrationPolicy{
		SeedUsers: &SeedUsersMigration{
			From:     []string{"alice", "bob"},
			To:       []string{"alice", "carol"},
			Strategy: SeedUsersStrategyPreserveExisting,
		},
	}
	if err := desired.Validate(); err != nil {
		t.Fatalf("valid seedUsers migration policy rejected: %v", err)
	}
	move, err := desired.AuthorizedSeedUserMigration(previous)
	if err != nil || move == nil {
		t.Fatalf("AuthorizedSeedUserMigration = (%#v, %v), want authorized move", move, err)
	}

	// Once applied, retaining the exact migrationPolicy in desired.json as an
	// audit record must not block a subsequent unrelated migration or reconcile.
	applied := desired
	followUp := applied
	followUp.Deployment.Ports = cloneMap(applied.Deployment.Ports)
	followUp.Deployment.Ports[profile.AWG2]++
	retainedSeedMove, err := followUp.AuthorizedSeedUserMigration(applied)
	if err != nil || retainedSeedMove != nil {
		t.Fatalf("retained seedUsers policy = (%#v, %v), want (nil, nil)", retainedSeedMove, err)
	}

	// Retaining a subnet migration audit record while performing a seedUsers
	// migration (or vice versa) must also succeed without re-triggering the old move.
	subnetApplied := Default([]string{"alice", "bob"})
	subnetApplied.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	subnetApplied.MigrationPolicy = &MigrationPolicy{
		Subnets: map[profile.Protocol]SubnetMigration{
			profile.AWG2: {From: "10.10.0.0/24", To: "10.99.0.0/24", Strategy: SubnetStrategyPreserveHost},
		},
	}
	combined := subnetApplied
	combined.Bootstrap.SeedUsers = []string{"alice", "carol"}
	combined.MigrationPolicy = &MigrationPolicy{
		Subnets: cloneMap(subnetApplied.MigrationPolicy.Subnets),
		SeedUsers: &SeedUsersMigration{
			From:     []string{"alice", "bob"},
			To:       []string{"alice", "carol"},
			Strategy: SeedUsersStrategyPreserveExisting,
		},
	}
	subnetMoves, err := combined.AuthorizedSubnetMigrations(subnetApplied)
	if err != nil || len(subnetMoves) != 0 {
		t.Fatalf("retained subnet policy = (%#v, %v), want empty moves and nil err", subnetMoves, err)
	}
	seedMove, err := combined.AuthorizedSeedUserMigration(subnetApplied)
	if err != nil || seedMove == nil {
		t.Fatalf("combined seedUsers move = (%#v, %v), want authorized move", seedMove, err)
	}

	invalid := map[string]func(*State){
		"empty policy": func(s *State) {
			s.MigrationPolicy = &MigrationPolicy{}
		},
		"unknown strategy": func(s *State) {
			s.MigrationPolicy.SeedUsers.Strategy = "replace-all"
		},
		"identical from and to": func(s *State) {
			s.MigrationPolicy.SeedUsers.From = []string{"alice", "carol"}
		},
		"mismatched to": func(s *State) {
			s.MigrationPolicy.SeedUsers.To = []string{"alice"}
		},
		"duplicate user in from": func(s *State) {
			s.MigrationPolicy.SeedUsers.From = []string{"alice", "alice"}
		},
		"empty user in to": func(s *State) {
			s.Bootstrap.SeedUsers = []string{"alice", ""}
			s.MigrationPolicy.SeedUsers.To = []string{"alice", ""}
		},
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			candidate := Default([]string{"alice", "carol"})
			candidate.MigrationPolicy = &MigrationPolicy{
				SeedUsers: &SeedUsersMigration{
					From:     []string{"alice", "bob"},
					To:       []string{"alice", "carol"},
					Strategy: SeedUsersStrategyPreserveExisting,
				},
			}
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate accepted invalid seedUsers migration policy")
			}
		})
	}
}

func TestTierBCertificateUnion(t *testing.T) {
	s := Default([]string{"alice"})
	s.Deployment.Tier = profile.TierB
	s.Deployment.Domain = "vpn.example.com"
	s.Deployment.Certificates = &Certificates{
		Source: profile.CertSourceACMEDNS,
		ACMEDNS: &ACMEDNS{
			Directory:     ACMEDefaultProvider,
			DataDirectory: profile.ACMEDefaultDataDirectory,
			Provider:      "cloudflare",
			Cloudflare:    &CloudflareDNS{APIToken: "cloudflare-token"},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid Tier B state rejected: %v", err)
	}

	s.Deployment.Certificates.Files = &CertificateFiles{CertificatePath: "/cert", KeyPath: "/key"}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("ambiguous certificate union error = %v", err)
	}
}

func TestDiffClassifiesMigrationAndReconcileChanges(t *testing.T) {
	before := Default([]string{"alice"})
	after := Default([]string{"alice"})
	after.Deployment.Image = "registry.example/core:next"
	after.Bot.Enabled = true
	after.Bot.AdminIDs = []int64{123}
	after.Bot.TelegramToken = "telegram-token"
	after.Bot.PublicHost = "vpn.example.com"
	after.Deployment.Ports[profile.AWG2]++

	changes, err := Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]ChangeClass{}
	for _, change := range changes {
		classes[change.Path] = change.Class
	}
	if classes["/deployment/image"] != Reconcile || classes["/bot"] != Reconcile {
		t.Fatalf("reconcilable changes classified incorrectly: %#v", classes)
	}
	if classes["/deployment/ports/awg-in"] != Migration || !RequiresMigration(changes) {
		t.Fatalf("migration change classified incorrectly: %#v", classes)
	}

	data, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("telegram-token-value")) {
		t.Fatal("diff unexpectedly contains a secret value")
	}
}

func TestDiffIgnoresSetOrdering(t *testing.T) {
	a := Default([]string{"alice"})
	b := Default([]string{"alice"})
	a.Bot.Enabled, b.Bot.Enabled = true, true
	a.Bot.TelegramToken, b.Bot.TelegramToken = "telegram-token", "telegram-token"
	a.Bot.PublicHost, b.Bot.PublicHost = "vpn.example.com", "vpn.example.com"
	a.Bot.AdminIDs = []int64{2, 1}
	b.Bot.AdminIDs = []int64{1, 2}
	changes, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("set ordering produced changes: %#v", changes)
	}
}

func TestCredentialRotationPolicyIsOneShotAndValidated(t *testing.T) {
	previous := Default([]string{"alice", "bob"})
	desired := Default([]string{"alice", "bob"})
	desired.MigrationPolicy = &MigrationPolicy{RotateCredentials: &CredentialRotation{
		ID: "20261104T120000Z-0a1b2c3d", Users: []string{"alice", "telegram-42"}, Strategy: CredentialRotationStrategyReissue,
	}}
	if err := desired.Validate(); err != nil {
		t.Fatalf("valid rotation rejected: %v", err)
	}
	rotation, err := desired.AuthorizedCredentialRotation(previous)
	if err != nil || rotation == nil || rotation.ID != "20261104T120000Z-0a1b2c3d" {
		t.Fatalf("AuthorizedCredentialRotation = (%#v, %v)", rotation, err)
	}
	changes, err := Diff(previous, desired)
	if err != nil || !RequiresMigration(changes) {
		t.Fatalf("a rotation request is not a migration: %#v %v", changes, err)
	}

	// The applied entry is now an audit record and rotates nothing again.
	if again, err := desired.AuthorizedCredentialRotation(desired); err != nil || again != nil {
		t.Fatalf("retained rotation record = (%#v, %v), want (nil, nil)", again, err)
	}
	next := desired
	next.MigrationPolicy = &MigrationPolicy{RotateCredentials: &CredentialRotation{
		ID: "20261105T120000Z-ffffffff", Users: []string{"alice"}, Strategy: CredentialRotationStrategyReissue,
	}}
	if again, err := next.AuthorizedCredentialRotation(desired); err != nil || again == nil {
		t.Fatalf("a new id did not request a new rotation: (%#v, %v)", again, err)
	}
	reused := desired
	reused.MigrationPolicy = &MigrationPolicy{RotateCredentials: &CredentialRotation{
		ID: "20261104T120000Z-0a1b2c3d", Users: []string{"bob"}, Strategy: CredentialRotationStrategyReissue,
	}}
	if _, err := reused.AuthorizedCredentialRotation(desired); err == nil {
		t.Fatal("a reused id for a different rotation was accepted")
	}

	for name, rotation := range map[string]CredentialRotation{
		"empty id":       {ID: "", Users: []string{"alice"}, Strategy: CredentialRotationStrategyReissue},
		"unsafe id":      {ID: "../x", Users: []string{"alice"}, Strategy: CredentialRotationStrategyReissue},
		"long id":        {ID: strings.Repeat("a", 65), Users: []string{"alice"}, Strategy: CredentialRotationStrategyReissue},
		"no users":       {ID: "r", Users: nil, Strategy: CredentialRotationStrategyReissue},
		"duplicate user": {ID: "r", Users: []string{"alice", "alice"}, Strategy: CredentialRotationStrategyReissue},
		"unsorted users": {ID: "r", Users: []string{"bob", "alice"}, Strategy: CredentialRotationStrategyReissue},
		"bad strategy":   {ID: "r", Users: []string{"alice"}, Strategy: "regenerate-everything"},
	} {
		bad := Default([]string{"alice"})
		copied := rotation
		bad.MigrationPolicy = &MigrationPolicy{RotateCredentials: &copied}
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: invalid rotation accepted", name)
		}
	}
}
