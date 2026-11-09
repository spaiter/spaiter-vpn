package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/control"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestControlSettingsTouchOnlyWhatTheyName(t *testing.T) {
	current := state.Default([]string{"owner"})
	current.MigrationPolicy = &state.MigrationPolicy{RotateCredentials: &state.CredentialRotation{ID: "r1", Users: []string{"owner"}, Strategy: state.CredentialRotationStrategyReissue}}
	before := current.Deployment.Ports[profile.AWG2]
	desired, err := controlDesired(current, control.Change{
		Kind: control.ChangeSettings, Ports: map[string]uint16{"awg-in": before + 1}, Disable: []string{"mieru-in"},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if desired.Deployment.Ports[profile.AWG2] != before+1 || current.Deployment.Ports[profile.AWG2] != before {
		t.Fatal("the port change was not applied, or it leaked into the current state")
	}
	if len(desired.Deployment.Protocols.Disabled) != 1 || desired.MigrationPolicy == nil || desired.MigrationPolicy.RotateCredentials == nil {
		t.Fatalf("desired = %#v", desired.Deployment.Protocols)
	}
	if _, err := controlDesired(current, control.Change{Kind: control.ChangeSettings, Ports: map[string]uint16{"ssh": 22}}, time.Now()); err == nil {
		t.Fatal("an unknown protocol was accepted")
	}
}

func TestControlImageStaysInTheDeployedRepository(t *testing.T) {
	current := state.Default([]string{"owner"})
	repo := imageRepository(current.Deployment.Image)
	desired, err := controlDesired(current, control.Change{Kind: control.ChangeImage, Image: repo + ":next"}, time.Now())
	if err != nil || desired.Deployment.Image != repo+":next" {
		t.Fatalf("same-repository update = %v, %v", desired.Deployment.Image, err)
	}
	for _, image := range []string{"evil.example/core:1", repo + "-fork:1", repo + ":latest"} {
		if _, err := controlDesired(current, control.Change{Kind: control.ChangeImage, Image: image}, time.Now()); err == nil {
			t.Errorf("image %s was accepted", image)
		}
	}
	if got := imageRepository("reg.example:5000/a/b@sha256:abc"); got != "reg.example:5000/a/b" {
		t.Fatalf("imageRepository = %s", got)
	}
	if got := imageRepository("reg.example:5000/a/b:tag"); got != "reg.example:5000/a/b" {
		t.Fatalf("imageRepository = %s", got)
	}
}

func TestControlRotationIsAFreshOneShotRequest(t *testing.T) {
	current := state.Default([]string{"owner"})
	desired, err := controlDesired(current, control.Change{Kind: control.ChangeRotate, Users: []string{"owner"}}, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil || desired.MigrationPolicy == nil || !strings.HasPrefix(desired.MigrationPolicy.RotateCredentials.ID, "20261105T000000Z-") {
		t.Fatalf("rotation desired = %#v, %v", desired.MigrationPolicy, err)
	}
}
