package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonical returns a normalised copy. Only fields whose semantics are sets
// are sorted. SeedUsers intentionally retains order because the generator uses
// it when assigning WireGuard peer addresses.
func (s State) Canonical() (State, error) {
	if err := s.Validate(); err != nil {
		return State{}, err
	}
	result := s
	result.Deployment.Protocols.Disabled = sortedProtocolNames(s.Deployment.Protocols.Disabled)
	result.Deployment.XDPInterfaces = make([]string, len(s.Deployment.XDPInterfaces))
	copy(result.Deployment.XDPInterfaces, s.Deployment.XDPInterfaces)
	if !(len(result.Deployment.XDPInterfaces) == 1 && result.Deployment.XDPInterfaces[0] == "auto") {
		sort.Strings(result.Deployment.XDPInterfaces)
	}
	result.Bootstrap.SeedUsers = append([]string(nil), s.Bootstrap.SeedUsers...)
	result.Bot.AdminIDs = make([]int64, len(s.Bot.AdminIDs))
	copy(result.Bot.AdminIDs, s.Bot.AdminIDs)
	sort.Slice(result.Bot.AdminIDs, func(i, j int) bool { return result.Bot.AdminIDs[i] < result.Bot.AdminIDs[j] })
	result.Deployment.Ports = cloneMap(s.Deployment.Ports)
	result.Deployment.Subnets = cloneMap(s.Deployment.Subnets)
	result.Deployment.MTU = cloneMap(s.Deployment.MTU)
	if s.MigrationPolicy != nil {
		copied := &MigrationPolicy{}
		if s.MigrationPolicy.Subnets != nil {
			copied.Subnets = cloneMap(s.MigrationPolicy.Subnets)
		}
		if s.MigrationPolicy.SeedUsers != nil {
			copied.SeedUsers = &SeedUsersMigration{
				From:     append([]string(nil), s.MigrationPolicy.SeedUsers.From...),
				To:       append([]string(nil), s.MigrationPolicy.SeedUsers.To...),
				Strategy: s.MigrationPolicy.SeedUsers.Strategy,
			}
		}
		if s.MigrationPolicy.RotateCredentials != nil {
			copied.RotateCredentials = &CredentialRotation{
				ID:       s.MigrationPolicy.RotateCredentials.ID,
				Users:    append([]string(nil), s.MigrationPolicy.RotateCredentials.Users...),
				Strategy: s.MigrationPolicy.RotateCredentials.Strategy,
			}
		}
		result.MigrationPolicy = copied
	}
	if s.DDNS != nil {
		d := *s.DDNS
		result.DDNS = &d
	}
	if s.Web != nil {
		web := *s.Web
		result.Web = &web
	}
	return result, nil
}

// MarshalCanonical is the stable byte representation used by plans and apply
// consent. encoding/json sorts string map keys, while Canonical handles set
// slices explicitly.
func (s State) MarshalCanonical() ([]byte, error) {
	canonical, err := s.Canonical()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical desired state: %w", err)
	}
	return data, nil
}

// MarshalIndent returns the canonical human-facing document with a trailing
// newline, suitable for desired.json.
func (s State) MarshalIndent() ([]byte, error) {
	canonical, err := s.Canonical()
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal desired state: %w", err)
	}
	return append(data, '\n'), nil
}

func (s State) Digest() (string, error) {
	data, err := s.MarshalCanonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
