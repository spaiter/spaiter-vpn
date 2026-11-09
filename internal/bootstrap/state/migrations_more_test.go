package state

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func movedSubnet() (previous, proposed State) {
	previous = Default([]string{"alice"})
	proposed = Default([]string{"alice"})
	from := previous.Deployment.Subnets[profile.AWG2]
	proposed.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	proposed.MigrationPolicy = &MigrationPolicy{Subnets: map[profile.Protocol]SubnetMigration{
		profile.AWG2: {From: from, To: "10.99.0.0/24", Strategy: SubnetStrategyPreserveHost},
	}}
	return previous, proposed
}

func TestASubnetMoveNeedsAnExactAuthorization(t *testing.T) {
	previous, proposed := movedSubnet()
	moves, err := proposed.AuthorizedSubnetMigrations(previous)
	if err != nil || len(moves) != 1 || moves[profile.AWG2].To != "10.99.0.0/24" {
		t.Fatalf("authorized move: %v %v", moves, err)
	}

	bare := proposed
	bare.MigrationPolicy = nil
	if _, err := bare.AuthorizedSubnetMigrations(previous); err == nil || !strings.Contains(err.Error(), "without migrationPolicy") {
		t.Errorf("move without a policy: %v", err)
	}

	wrongFrom := proposed
	wrongFrom.MigrationPolicy = &MigrationPolicy{Subnets: map[profile.Protocol]SubnetMigration{
		profile.AWG2: {From: "10.1.0.0/24", To: "10.99.0.0/24", Strategy: SubnetStrategyPreserveHost},
	}}
	if _, err := wrongFrom.AuthorizedSubnetMigrations(previous); err == nil || !strings.Contains(err.Error(), "exact preserve-host") {
		t.Errorf("wrong source: %v", err)
	}

	// A policy that accompanies no move is refused, unless it is the record of one already made.
	idle := Default([]string{"alice"})
	idle.MigrationPolicy = &MigrationPolicy{Subnets: map[profile.Protocol]SubnetMigration{
		profile.AWG3: {From: "10.1.0.0/24", To: idle.Deployment.Subnets[profile.AWG3], Strategy: SubnetStrategyPreserveHost},
	}}
	if _, err := idle.AuthorizedSubnetMigrations(Default([]string{"alice"})); err == nil || !strings.Contains(err.Error(), "does not accompany") {
		t.Errorf("idle policy: %v", err)
	}
	done := idle
	record := Default([]string{"alice"})
	record.MigrationPolicy = idle.MigrationPolicy
	if moves, err := done.AuthorizedSubnetMigrations(record); err != nil || len(moves) != 0 {
		t.Errorf("retained audit record: %v %v", moves, err)
	}
}

func TestSeedUserChangesNeedAMatchingPolicyAndRetainedRecordsAreNotRepeated(t *testing.T) {
	previous := Default([]string{"alice"})
	proposed := Default([]string{"alice", "bob"})

	if _, err := proposed.AuthorizedSeedUserMigration(previous); err == nil || !strings.Contains(err.Error(), "without migrationPolicy.seedUsers") {
		t.Errorf("no policy: %v", err)
	}
	policy := &SeedUsersMigration{From: []string{"alice"}, To: []string{"alice", "bob"}, Strategy: SeedUsersStrategyPreserveExisting}
	proposed.MigrationPolicy = &MigrationPolicy{SeedUsers: policy}
	got, err := proposed.AuthorizedSeedUserMigration(previous)
	if err != nil || got == nil || len(got.To) != 2 {
		t.Fatalf("authorized: %v %v", got, err)
	}
	got.To[0] = "mutated"
	if policy.To[0] == "mutated" {
		t.Error("the returned migration shares memory with the policy")
	}

	stale := Default([]string{"alice", "bob"})
	stale.MigrationPolicy = &MigrationPolicy{SeedUsers: &SeedUsersMigration{From: []string{"alice"}, To: []string{"alice", "carol"}, Strategy: SeedUsersStrategyPreserveExisting}}
	if _, err := stale.AuthorizedSeedUserMigration(previous); err == nil || !strings.Contains(err.Error(), "exact preserve-existing") {
		t.Errorf("wrong target: %v", err)
	}

	// Unchanged users with a leftover policy: fine only as the previous record.
	same := Default([]string{"alice", "bob"})
	same.MigrationPolicy = &MigrationPolicy{SeedUsers: policy}
	if _, err := same.AuthorizedSeedUserMigration(Default([]string{"alice", "bob"})); err == nil || !strings.Contains(err.Error(), "does not accompany") {
		t.Errorf("leftover policy: %v", err)
	}
	recorded := Default([]string{"alice", "bob"})
	recorded.MigrationPolicy = &MigrationPolicy{SeedUsers: policy}
	if got, err := same.AuthorizedSeedUserMigration(recorded); err != nil || got != nil {
		t.Errorf("retained record: %v %v", got, err)
	}
	if got, err := Default([]string{"a"}).AuthorizedSeedUserMigration(Default([]string{"a"})); err != nil || got != nil {
		t.Errorf("no change: %v %v", got, err)
	}
}

func TestCredentialRotationIDsAreOneShot(t *testing.T) {
	rotation := func(id string, users ...string) *MigrationPolicy {
		return &MigrationPolicy{RotateCredentials: &CredentialRotation{ID: id, Users: users, Strategy: CredentialRotationStrategyReissue}}
	}
	previous := Default([]string{"alice"})
	previous.MigrationPolicy = rotation("r1", "alice")

	same := Default([]string{"alice"})
	same.MigrationPolicy = rotation("r1", "alice")
	if got, err := same.AuthorizedCredentialRotation(previous); err != nil || got != nil {
		t.Errorf("a retained record asked for another rotation: %v %v", got, err)
	}
	reused := Default([]string{"alice"})
	reused.MigrationPolicy = rotation("r1", "alice", "bob")
	if _, err := reused.AuthorizedCredentialRotation(previous); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("a reused id: %v", err)
	}
	fresh := Default([]string{"alice"})
	fresh.MigrationPolicy = rotation("r2", "alice")
	if got, err := fresh.AuthorizedCredentialRotation(previous); err != nil || got == nil || got.ID != "r2" {
		t.Errorf("a new rotation: %v %v", got, err)
	}
	if got, err := Default([]string{"alice"}).AuthorizedCredentialRotation(previous); err != nil || got != nil {
		t.Errorf("no rotation requested: %v %v", got, err)
	}
	odd := Default([]string{"alice"})
	odd.MigrationPolicy = &MigrationPolicy{RotateCredentials: &CredentialRotation{ID: "r3", Users: []string{"alice"}, Strategy: "burn"}}
	if _, err := odd.AuthorizedCredentialRotation(Default([]string{"alice"})); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("unknown strategy: %v", err)
	}
}

func TestParseIsStrictAboutShapeAndNulls(t *testing.T) {
	good, err := Default([]string{"alice"}).MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	mutate := func(edit func(map[string]any)) []byte {
		var copyDoc map[string]any
		json.Unmarshal(good, &copyDoc)
		edit(copyDoc)
		out, _ := json.Marshal(copyDoc)
		return out
	}
	cases := map[string][]byte{
		"a required field is missing": mutate(func(d map[string]any) { delete(d["deployment"].(map[string]any), "image") }),
		"a nested field is missing": mutate(func(d map[string]any) {
			delete(d["deployment"].(map[string]any)["realityHandshake"].(map[string]any), "port")
		}),
		"an object is null":       mutate(func(d map[string]any) { d["bootstrap"] = nil }),
		"a nested object is null": mutate(func(d map[string]any) { d["deployment"].(map[string]any)["realityHandshake"] = nil }),
		"a duplicate key":         bytes.Replace(good, []byte(`"apiVersion"`), []byte(`"apiVersion": "x", "apiVersion"`), 1),
		"not an object":           []byte(`[]`),
		"empty":                   nil,
	}
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: Parse accepted it", name)
		}
	}
	if _, err := Decode(bytes.NewReader(good)); err != nil {
		t.Errorf("Decode of a good document: %v", err)
	}
	if _, err := Decode(errReader{}); err == nil || !strings.Contains(err.Error(), "read desired state") {
		t.Errorf("Decode of a failing reader: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, bytes.ErrTooLarge }

func TestCanonicalFormIsStableAndRefusesInvalidState(t *testing.T) {
	a := Default([]string{"alice"})
	a.Deployment.XDPInterfaces = []string{"eth1", "eth0"}
	a.Bot.AdminIDs = []int64{9, 3}
	canonical, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Deployment.XDPInterfaces[0] != "eth0" || canonical.Bot.AdminIDs[0] != 3 {
		t.Errorf("sets were not sorted: %v %v", canonical.Deployment.XDPInterfaces, canonical.Bot.AdminIDs)
	}
	if a.Deployment.XDPInterfaces[0] != "eth1" || a.Bot.AdminIDs[0] != 9 {
		t.Error("Canonical sorted the original in place")
	}
	b := a
	b.Deployment.XDPInterfaces = []string{"eth0", "eth1"}
	b.Bot.AdminIDs = []int64{3, 9}
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da == "" || da != db {
		t.Errorf("digests of equal sets differ: %q %q", da, db)
	}
	text, err := a.MarshalIndent()
	if err != nil || !bytes.HasSuffix(text, []byte("\n")) {
		t.Errorf("MarshalIndent: %v %q", err, text[len(text)-3:])
	}

	broken := Default([]string{"alice"})
	broken.Deployment.Image = "repo/core:latest"
	if _, err := broken.Canonical(); err == nil {
		t.Error("Canonical accepted an invalid state")
	}
	if _, err := broken.MarshalCanonical(); err == nil {
		t.Error("MarshalCanonical accepted an invalid state")
	}
	if _, err := broken.MarshalIndent(); err == nil {
		t.Error("MarshalIndent accepted an invalid state")
	}
	if _, err := broken.Digest(); err == nil {
		t.Error("Digest accepted an invalid state")
	}
}

func TestRequiresMigrationLooksOnlyAtMigrationChanges(t *testing.T) {
	if RequiresMigration(nil) || RequiresMigration([]Change{{Class: Reconcile}}) {
		t.Error("a reconcile-only change was called a migration")
	}
	if !RequiresMigration([]Change{{Class: Reconcile}, {Class: Migration}}) {
		t.Error("a migration was missed")
	}
}
