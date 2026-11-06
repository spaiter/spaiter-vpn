package state

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
)

// Subscription is one row of the token registry.
type Subscription struct {
	UID     string `json:"uid"`
	Created string `json:"created"`
	// LastHash is the structural hash of the bundle this subscriber was last
	// notified about. The loop compares against it to nudge users on a real
	// change and stay quiet through routine pool rotation.
	LastHash string `json:"last_hash,omitempty"`
}

// Subscriptions is the registry, keyed by token.
type Subscriptions map[string]Subscription

// Subscriptions reads the registry.
func (s *Store) Subscriptions() (Subscriptions, error) {
	out := Subscriptions{}
	_, err := readJSON(s.subsPath(), &out)
	return out, err
}

func (s *Store) subsPath() string { return s.Path("wdtt", "subs.json") }

// UpdateSubscriptions applies mutate to the registry under a lock, re-reading
// it first.
//
// Re-reading rather than writing back a snapshot taken earlier is the point:
// the refresh loop holds its view across every bundle rebuild, and a
// subscription issued meanwhile must survive while one deleted meanwhile must
// not come back.
func (s *Store) UpdateSubscriptions(mutate func(Subscriptions) error) error {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()

	subs, err := s.Subscriptions()
	if err != nil {
		return err
	}
	if err := mutate(subs); err != nil {
		return err
	}
	// 0644: the subscription server reads this, and it holds tokens rather
	// than keys -- the secret is the URL the user already has.
	return writeJSON(s.subsPath(), subs, 0o644)
}

// SubscriptionToken returns the user's stable token, creating one on first
// use. One token per user, reused across regenerations, so a link handed out
// once keeps working.
func (s *Store) SubscriptionToken(uid string) (string, error) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()

	subs, err := s.Subscriptions()
	if err != nil {
		return "", err
	}
	for token, sub := range subs {
		if sub.UID == uid {
			return token, nil
		}
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	subs[token] = Subscription{UID: uid, Created: Now()}
	if err := writeJSON(s.subsPath(), subs, 0o644); err != nil {
		return "", err
	}
	return token, nil
}

// NewToken mints a token in the registry's format for a writer outside the
// bot, which bootstrap's credential rotation is.
func NewToken() (string, error) { return newToken() }

// newToken mints an unguessable token. 24 random bytes, URL-safe: the token is
// the only thing gating the subscription, at the same trust level as the
// per-user credentials already inside what it serves.
func newToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("state: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BundleCache reads the prebuilt bundle for a token. The subscription server
// serves this verbatim, so a poll costs no provisioning.
func (s *Store) BundleCache(token string) ([]byte, bool, error) {
	data, err := os.ReadFile(s.bundlePath(token))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("state: read bundle cache: %w", err)
	}
	return data, true, nil
}

// SetBundleCache stores a prebuilt bundle.
func (s *Store) SetBundleCache(token string, bundle []byte) error {
	return writeAtomic(s.bundlePath(token), bundle, 0o644)
}

func (s *Store) bundlePath(token string) string {
	// The token is random base64url, so it cannot escape the directory; it is
	// still passed through Base to keep that true if the format ever changes.
	return s.Path("wdtt", "subs-cache", safeName(token)+".json")
}

// safeName strips anything that could leave the directory. A token arrives
// from an HTTP path, and the one thing it must never do is address a file
// elsewhere.
func safeName(token string) string {
	out := make([]rune, 0, len(token))
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		}
	}
	return string(out)
}

// VKHash is one entry of the VK call hash pool.
type VKHash struct {
	Status  string `json:"status,omitempty"`
	Checked string `json:"checked,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Added   string `json:"added,omitempty"`
	// By and ByName attribute a manually submitted link, so the submitter can
	// be told when it dies. Absent for entries the holder service publishes.
	By     int64  `json:"by,omitempty"`
	ByName string `json:"by_name,omitempty"`
}

// VKHashes is the pool, keyed by hash.
type VKHashes map[string]VKHash

// VKHashes reads the pool.
func (s *Store) VKHashes() (VKHashes, error) {
	out := VKHashes{}
	_, err := readJSON(s.vkPath(), &out)
	return out, err
}

func (s *Store) vkPath() string { return s.Path("wdtt", "vk_hashes.json") }

// UpdateVKHashes applies mutate to the pool under the same re-read discipline
// as the subscriptions: the validation loop awaits a helper per hash, and a
// link submitted meanwhile must not be lost.
func (s *Store) UpdateVKHashes(mutate func(VKHashes) error) error {
	s.vkMu.Lock()
	defer s.vkMu.Unlock()

	hashes, err := s.VKHashes()
	if err != nil {
		return err
	}
	if err := mutate(hashes); err != nil {
		return err
	}
	return writeJSON(s.vkPath(), hashes, 0o644)
}

// LiveVKHashes are the hashes handed to clients, in a stable order so a bundle
// rebuilt from an unchanged pool comes out unchanged.
//
// "Not dead" rather than "ok": a hash whose last check was inconclusive --
// captcha, rate limit, a network blip -- is still worth handing out, and
// demanding "ok" would empty the pool on a bad check run. If everything is
// dead they go out anyway, because a client with stale hashes can still find
// a live relay, while a client with none has nothing to try. fallback is the
// configured pool, used only when there is no file at all.
func (s *Store) LiveVKHashes(fallback []string) ([]string, error) {
	hashes, err := s.VKHashes()
	if err != nil {
		return nil, err
	}
	live := make([]string, 0, len(hashes))
	for hash, entry := range hashes {
		if entry.Status != "dead" {
			live = append(live, hash)
		}
	}
	if len(live) == 0 {
		for hash := range hashes {
			live = append(live, hash)
		}
	}
	if len(live) == 0 {
		return fallback, nil
	}
	slices.Sort(live)
	return live, nil
}

// SubscriptionBase is where the subscription links last handed out pointed, as
// the bot recorded it. A change means every subscriber holds a link to an
// address the bot no longer serves, which their client cannot discover by
// polling it.
type SubscriptionBase struct {
	HostCF     string `json:"host_cf,omitempty"`
	HostDirect string `json:"host_direct,omitempty"`
}

func (s *Store) subscriptionBasePath() string { return s.Path("subscription-base.json") }

// SubscriptionBase reads the recorded base; found is false before the first
// record, which is not a change.
func (s *Store) SubscriptionBase() (base SubscriptionBase, found bool, err error) {
	found, err = readJSON(s.subscriptionBasePath(), &base)
	return base, found, err
}

// SetSubscriptionBase records the base the current links point at.
func (s *Store) SetSubscriptionBase(base SubscriptionBase) error {
	return writeJSON(s.subscriptionBasePath(), base, 0o600)
}
