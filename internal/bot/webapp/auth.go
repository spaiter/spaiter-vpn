package webapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Telegram signs what it hands a Mini App: the user, the chat, an auth_date,
// all as a query string with an HMAC over the sorted pairs keyed by the bot
// token. Checking it here is the whole of authentication -- there is no
// login, no cookie, no session; every request carries the signed string and is
// checked afresh. See https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
//
// The library has a validator, but it unescapes already-parsed values a second
// time and never looks at auth_date, so it is not used.

// ErrUnauthenticated is a request without a valid signature.
var ErrUnauthenticated = errors.New("webapp: init data is missing, malformed or not signed by this bot")

// ErrStale is a signature that is valid but too old. A signed string is a
// bearer credential for as long as it is accepted, so it is not accepted for
// long: Telegram issues a fresh one every time the app opens.
var ErrStale = errors.New("webapp: init data is too old, reopen the app")

// maxAge is how long a signed init string is honoured.
const maxAge = 12 * time.Hour

// User is who Telegram says opened the app.
type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
}

// Verify checks a raw initData string against the bot token and returns the
// user inside it.
func Verify(initData, token string, now time.Time) (User, error) {
	values, err := url.ParseQuery(initData)
	if err != nil || initData == "" {
		return User{}, ErrUnauthenticated
	}
	hash := values.Get("hash")
	if hash == "" {
		return User{}, ErrUnauthenticated
	}
	values.Del("hash")

	// data-check-string: every field, as "key=value" in key order, newline
	// separated. Values are used as parsed -- ParseQuery already unescaped
	// them, and that is the form Telegram signed.
	pairs := make([]string, 0, len(values))
	for key, list := range values {
		for _, value := range list {
			pairs = append(pairs, key+"="+value)
		}
	}
	sort.Strings(pairs)

	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(token))
	mac := hmac.New(sha256.New, secret.Sum(nil))
	mac.Write([]byte(strings.Join(pairs, "\n")))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(hash)
	if err != nil || !hmac.Equal(got, want) {
		return User{}, ErrUnauthenticated
	}

	issued, err := strconv.ParseInt(values.Get("auth_date"), 10, 64)
	if err != nil {
		return User{}, ErrUnauthenticated
	}
	age := now.Sub(time.Unix(issued, 0))
	if age > maxAge || age < -5*time.Minute {
		return User{}, ErrStale
	}

	var user User
	if err := json.Unmarshal([]byte(values.Get("user")), &user); err != nil || user.ID == 0 {
		return User{}, ErrUnauthenticated
	}
	return user, nil
}

// Sign produces an initData string the way Telegram would. It exists for the
// tests and for a local run against a stub token; it is not reachable from any
// handler.
func Sign(fields url.Values, token string) string {
	fields.Del("hash")
	pairs := make([]string, 0, len(fields))
	for key, list := range fields {
		for _, value := range list {
			pairs = append(pairs, key+"="+value)
		}
	}
	sort.Strings(pairs)
	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(token))
	mac := hmac.New(sha256.New, secret.Sum(nil))
	mac.Write([]byte(strings.Join(pairs, "\n")))
	fields.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	return fields.Encode()
}
