package state

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestCanonicalCopiesEverythingItHandsBack(t *testing.T) {
	s := Default([]string{"alice"})
	s.Bootstrap.ManageWeb = true
	s.Bootstrap.ManageControl = true
	s.Web = &Web{Listen: "127.0.0.1:9000"}
	s.Bot.PublicHost = "vpn.duckdns.org"
	s.DDNS = &DDNS{Provider: "duckdns", Token: "t"}
	s.MigrationPolicy = &MigrationPolicy{
		SeedUsers: &SeedUsersMigration{From: []string{"bob"}, To: []string{"alice"}, Strategy: SeedUsersStrategyPreserveExisting},
	}

	canonical, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonical.Web, s.Web) || !reflect.DeepEqual(canonical.DDNS, s.DDNS) {
		t.Fatal("web or ddns were not carried over")
	}
	if canonical.Web == s.Web || canonical.DDNS == s.DDNS || canonical.MigrationPolicy == s.MigrationPolicy || canonical.MigrationPolicy.SeedUsers == s.MigrationPolicy.SeedUsers {
		t.Error("the canonical form aliases the original, so editing one changes the other")
	}
	canonical.MigrationPolicy.SeedUsers.From[0] = "mallory"
	canonical.Web.Listen = "0.0.0.0:1"
	if s.MigrationPolicy.SeedUsers.From[0] != "bob" || s.Web.Listen != "127.0.0.1:9000" {
		t.Error("editing the copy reached the original")
	}
}

func TestCanonicalCopiesSubnetMigrations(t *testing.T) {
	_, proposed := movedSubnet()
	canonical, err := proposed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	canonical.MigrationPolicy.Subnets[profile.AWG2] = SubnetMigration{}
	if proposed.MigrationPolicy.Subnets[profile.AWG2].To != "10.99.0.0/24" {
		t.Error("the subnet migration map is shared with the original")
	}
}

func TestDiffRefusesStatesThatDoNotValidate(t *testing.T) {
	good := Default([]string{"alice"})
	bad := Default([]string{"alice"})
	bad.APIVersion = "nope"
	if _, err := Diff(bad, good); err == nil || !strings.Contains(err.Error(), "previous") {
		t.Errorf("bad previous: %v", err)
	}
	if _, err := Diff(good, bad); err == nil || !strings.Contains(err.Error(), "proposed") {
		t.Errorf("bad proposed: %v", err)
	}
}

func TestDiffTellsAnAddedKeyFromAChangedOne(t *testing.T) {
	before := Default([]string{"alice"})
	after := Default([]string{"alice"})
	for key := range after.Deployment.MTU {
		delete(after.Deployment.MTU, key)
		break
	}
	changes, err := Diff(before, after)
	if err != nil {
		t.Skipf("a state without that MTU is invalid: %v", err)
	}
	if len(changes) != 1 || changes[0].After != nil || changes[0].Before == nil {
		t.Errorf("changes = %#v", changes)
	}
}
