package state

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

type ChangeClass string

const (
	Reconcile ChangeClass = "reconcile"
	Migration ChangeClass = "migration"
)

type Change struct {
	Path   string      `json:"path"`
	Class  ChangeClass `json:"class"`
	Before any         `json:"before"`
	After  any         `json:"after"`
}

// Diff separates changes to surrounding managed files from changes that need
// a config migration. The planner further divides migrations into those the
// live management API supports and those requiring an operator procedure.
func Diff(before, after State) ([]Change, error) {
	left, err := before.Canonical()
	if err != nil {
		return nil, fmt.Errorf("validate previous desired state: %w", err)
	}
	right, err := after.Canonical()
	if err != nil {
		return nil, fmt.Errorf("validate proposed desired state: %w", err)
	}

	var changes []Change
	compare := func(path string, class ChangeClass, oldValue, newValue any) {
		if !reflect.DeepEqual(oldValue, newValue) {
			changes = append(changes, Change{Path: path, Class: class, Before: oldValue, After: newValue})
		}
	}

	compare("/apiVersion", Migration, left.APIVersion, right.APIVersion)
	compare("/deployment/image", Reconcile, left.Deployment.Image, right.Deployment.Image)
	compare("/deployment/tier", Migration, left.Deployment.Tier, right.Deployment.Tier)
	compare("/deployment/protocols", Migration, left.Deployment.Protocols, right.Deployment.Protocols)
	compareProtocolMap(&changes, "/deployment/ports", Migration, left.Deployment.Ports, right.Deployment.Ports)
	compareProtocolMap(&changes, "/deployment/subnets", Migration, left.Deployment.Subnets, right.Deployment.Subnets)
	compareProtocolMap(&changes, "/deployment/mtu", Migration, left.Deployment.MTU, right.Deployment.MTU)
	compare("/deployment/xdpInterfaces", Migration, left.Deployment.XDPInterfaces, right.Deployment.XDPInterfaces)
	compare("/deployment/logLevel", Migration, left.Deployment.LogLevel, right.Deployment.LogLevel)
	compare("/deployment/domain", Migration, left.Deployment.Domain, right.Deployment.Domain)
	compare("/deployment/certificates", Migration, left.Deployment.Certificates, right.Deployment.Certificates)
	compare("/deployment/realityHandshake", Migration, left.Deployment.RealityHandshake, right.Deployment.RealityHandshake)
	compare("/deployment/shadowTlsHandshake", Migration, left.Deployment.ShadowTLSHandshake, right.Deployment.ShadowTLSHandshake)
	compare("/deployment/mtprotoFrontDomain", Migration, left.Deployment.MTProtoFrontDomain, right.Deployment.MTProtoFrontDomain)
	compare("/deployment/retireSharedMtproto", Migration, left.Deployment.RetireSharedMTProto, right.Deployment.RetireSharedMTProto)
	compare("/deployment/mtprotoPerUser", Migration, left.Deployment.MTProtoPerUser, right.Deployment.MTProtoPerUser)
	compare("/bootstrap/seedUsers", Migration, left.Bootstrap.SeedUsers, right.Bootstrap.SeedUsers)
	compare("/bootstrap/installDocker", Reconcile, left.Bootstrap.InstallDocker, right.Bootstrap.InstallDocker)
	compare("/bootstrap/manageFirewall", Reconcile, left.Bootstrap.ManageFirewall, right.Bootstrap.ManageFirewall)
	compare("/bootstrap/manageLogrotate", Reconcile, left.Bootstrap.ManageLogrotate, right.Bootstrap.ManageLogrotate)
	compare("/bootstrap/manageControl", Reconcile, left.Bootstrap.ManageControl, right.Bootstrap.ManageControl)
	compare("/bootstrap/manageWeb", Reconcile, left.Bootstrap.ManageWeb, right.Bootstrap.ManageWeb)
	compare("/web", Reconcile, left.Web, right.Web)
	compare("/ddns", Reconcile, left.DDNS, right.DDNS)
	compare("/bot", Reconcile, left.Bot, right.Bot)
	compare("/migrationPolicy", Migration, left.MigrationPolicy, right.MigrationPolicy)

	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

func compareProtocolMap[V comparable](changes *[]Change, path string, class ChangeClass, before, after map[profile.Protocol]V) {
	keys := map[profile.Protocol]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	ordered := make([]profile.Protocol, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, key := range ordered {
		oldValue, oldPresent := before[key]
		newValue, newPresent := after[key]
		if oldPresent != newPresent || oldValue != newValue {
			*changes = append(*changes, Change{
				Path: path + "/" + string(key), Class: class,
				Before: valueOrNil(oldValue, oldPresent), After: valueOrNil(newValue, newPresent),
			})
		}
	}
}

func valueOrNil[V any](value V, present bool) any {
	if !present {
		return nil
	}
	return value
}

func RequiresMigration(changes []Change) bool {
	for _, change := range changes {
		if change.Class == Migration {
			return true
		}
	}
	return false
}

// MarshalJSON is declared explicitly to ensure a future addition cannot
// accidentally include an unexported diagnostic or secret-bearing value.
func (c Change) MarshalJSON() ([]byte, error) {
	type wireChange struct {
		Path   string      `json:"path"`
		Class  ChangeClass `json:"class"`
		Before any         `json:"before"`
		After  any         `json:"after"`
	}
	return json.Marshal(wireChange(c))
}
