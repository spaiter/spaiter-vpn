package state

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// ClaimFile holds the one-time code that adopts a bot with no admin.
//
// Written by `spaiter-vpn bot claim-code` on the host, as root, and printed
// only there: holding the code proves access to the server's console, which
// "the first person to message the bot" never did. Only a hash is stored, so
// reading the bot's data directory does not reveal a usable code.
type ClaimFile struct {
	Hash     string    `json:"hash"`
	Expires  time.Time `json:"expires"`
	Attempts int       `json:"attempts"`
}

// MaxClaimAttempts bounds guessing: after this many wrong codes the claim is
// destroyed and a new one has to be issued locally.
const MaxClaimAttempts = 5

// claimAlphabet avoids characters that are easy to misread from a terminal.
const claimAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func (s *Store) claimPath() string { return s.Path("claim.json") }

// IssueClaim mints a code valid for ttl and stores its hash, replacing any
// earlier one. 12 characters from a 32-symbol alphabet is 60 bits, against at
// most MaxClaimAttempts guesses.
func (s *Store) IssueClaim(ttl time.Duration, now time.Time) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("state: random claim code: %w", err)
	}
	var code strings.Builder
	for i, b := range buf {
		if i > 0 && i%4 == 0 {
			code.WriteByte('-')
		}
		code.WriteByte(claimAlphabet[int(b)%len(claimAlphabet)])
	}
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	claim := ClaimFile{Hash: hashClaim(code.String()), Expires: now.Add(ttl).UTC()}
	if err := writeJSON(s.claimPath(), claim, 0o600); err != nil {
		return "", err
	}
	return code.String(), nil
}

// Claim makes uid an admin when code matches the outstanding claim. A wrong
// code counts against the claim; an expired or exhausted claim is destroyed.
// The claim is consumed by its first success, so a code shown once on a
// screen adopts the bot once.
func (s *Store) Claim(code string, uid int64, now time.Time) (bool, error) {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	var claim ClaimFile
	found, err := readJSON(s.claimPath(), &claim)
	if err != nil || !found {
		return false, err
	}
	if now.After(claim.Expires) || claim.Attempts >= MaxClaimAttempts {
		return false, s.removeClaim()
	}
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	if subtle.ConstantTimeCompare([]byte(hashClaim(normalized)), []byte(claim.Hash)) != 1 {
		claim.Attempts++
		if claim.Attempts >= MaxClaimAttempts {
			return false, s.removeClaim()
		}
		return false, writeJSON(s.claimPath(), claim, 0o600)
	}
	if err := s.appendID("admins.json", uid); err != nil {
		return false, err
	}
	return true, s.removeClaim()
}

func (s *Store) removeClaim() error {
	if err := os.Remove(s.claimPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func hashClaim(code string) string {
	sum := sha256.Sum256([]byte("spaiter-vpn-claim\x00" + code))
	return hex.EncodeToString(sum[:])
}
