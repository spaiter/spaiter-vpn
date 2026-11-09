package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	botstate "github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// relayFixture lays out the bot's data directory and an external relay config
// directory holding one rotated user's password, the way a live host has them.
type relayFixture struct {
	options Options
	relay   string // passwords.json
	copyOf  string // the bot's copy of the user's password
	peers   []rotatedRelayPeer
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	root := t.TempDir()
	layout := discover.Layout{ConfigRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "var")}
	f := &relayFixture{}
	f.options.Layout = layout
	f.options.Desired.Bot.WDTTConfigDirectory = filepath.Join(root, "relay")
	f.relay = filepath.Join(root, "relay", "passwords.json")
	f.copyOf = filepath.Join(layout.BotDataDir(), "wdtt", "7.json")
	for _, dir := range []string{filepath.Dir(f.relay), filepath.Dir(f.copyOf)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.write(t, f.relay, `{"passwords":{"oldpass":{"wg_priv":"PRIV","wg_ip":"10.0.0.2","device_id":"dev1","device_ids":["dev2"]}},"devices":{"dev1":{},"dev2":{},"keep":{}}}`)
	f.write(t, f.copyOf, `{"password":"oldpass"}`)
	f.peers = []rotatedRelayPeer{{
		old:     botPeerFile{path: "awg/7.json", uid: "7", value: botstate.Peer{Priv: "PRIV", IP: "10.0.0.2"}},
		newPriv: "NEWPRIV",
	}}
	return f
}

func (f *relayFixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *relayFixture) rotate() ([]transaction.Change, error) {
	return f.options.rotateRelayPasswords(&transaction.Manager{}, transaction.Receipt{}, f.peers)
}

func TestRelayPasswordRotationReissuesTheEntryAndDropsItsDevices(t *testing.T) {
	f := newRelayFixture(t)
	changes, err := f.rotate()
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 {
		t.Fatalf("changes = %d, want the password copy, the relay file and the reload marker", len(changes))
	}
	var relay struct {
		Passwords map[string]map[string]json.RawMessage `json:"passwords"`
		Devices   map[string]json.RawMessage            `json:"devices"`
	}
	for _, change := range changes {
		if change.Path == f.relay {
			if err := json.Unmarshal(change.Data, &relay); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, kept := relay.Passwords["oldpass"]; kept || len(relay.Passwords) != 1 {
		t.Errorf("passwords = %v", relay.Passwords)
	}
	for _, entry := range relay.Passwords {
		if string(entry["wg_priv"]) != `"NEWPRIV"` || entry["device_id"] != nil || entry["device_ids"] != nil {
			t.Errorf("entry = %v", entry)
		}
	}
	if len(relay.Devices) != 1 || relay.Devices["keep"] == nil {
		t.Errorf("devices = %v", relay.Devices)
	}
}

func TestRelayPasswordRotationWithoutPeersChangesNothing(t *testing.T) {
	f := newRelayFixture(t)
	f.peers = nil
	if changes, err := f.rotate(); err != nil || changes != nil {
		t.Errorf("changes = %v, %v", changes, err)
	}
}

func TestRelayPasswordRotationRefusesAnyInconsistency(t *testing.T) {
	cases := map[string]struct {
		break_ func(t *testing.T, f *relayFixture)
		want   string
	}{
		"no relay directory": {func(t *testing.T, f *relayFixture) { f.options.Desired.Bot.WDTTConfigDirectory = "" }, "does not name the external relay"},
		"no passwords file":  {func(t *testing.T, f *relayFixture) { os.Remove(f.relay) }, "read WG-over-VK relay passwords"},
		"passwords not json": {func(t *testing.T, f *relayFixture) { f.write(t, f.relay, "{") }, "parse WG-over-VK relay passwords"},
		"passwords missing":  {func(t *testing.T, f *relayFixture) { f.write(t, f.relay, `{"devices":{}}`) }, "passwords must be an object"},
		"passwords null":     {func(t *testing.T, f *relayFixture) { f.write(t, f.relay, `{"passwords":null}`) }, "passwords must be an object"},
		"devices not object": {func(t *testing.T, f *relayFixture) { f.write(t, f.relay, `{"passwords":{},"devices":[1]}`) }, "devices must be an object"},
		"no password copy":   {func(t *testing.T, f *relayFixture) { os.Remove(f.copyOf) }, "read WG-over-VK password copy"},
		"empty copy":         {func(t *testing.T, f *relayFixture) { f.write(t, f.copyOf, `{"password":""}`) }, "invalid WG-over-VK password copy"},
		"copy not json":      {func(t *testing.T, f *relayFixture) { f.write(t, f.copyOf, `{`) }, "invalid WG-over-VK password copy"},
		"no matching entry":  {func(t *testing.T, f *relayFixture) { f.write(t, f.copyOf, `{"password":"other"}`) }, "no matching relay passwords.json entry"},
		"priv not a string": {func(t *testing.T, f *relayFixture) {
			f.write(t, f.relay, `{"passwords":{"oldpass":{"wg_priv":1,"wg_ip":"10.0.0.2"}}}`)
		}, "wg_priv must be a string"},
		"ip not a string": {func(t *testing.T, f *relayFixture) {
			f.write(t, f.relay, `{"passwords":{"oldpass":{"wg_priv":"PRIV","wg_ip":1}}}`)
		}, "wg_ip must be a string"},
		"entry for another peer": {func(t *testing.T, f *relayFixture) {
			f.write(t, f.relay, `{"passwords":{"oldpass":{"wg_priv":"OTHER","wg_ip":"10.0.0.2"}}}`)
		}, "does not match bot peer"},
	}
	for name, tc := range cases {
		f := newRelayFixture(t)
		tc.break_(t, f)
		if _, err := f.rotate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBoundDevicesIgnoresTheMultiMarker(t *testing.T) {
	entry := map[string]json.RawMessage{"device_id": json.RawMessage(`"multi"`), "device_ids": json.RawMessage(`["a","b"]`)}
	if got := boundDevices(entry); len(got) != 2 {
		t.Errorf("devices = %v", got)
	}
	if got := boundDevices(map[string]json.RawMessage{"device_id": json.RawMessage(`7`)}); len(got) != 0 {
		t.Errorf("a non-string id = %v", got)
	}
}

func TestSubscriptionTokenRotationReplacesOnlyTheRotatedUsersTokens(t *testing.T) {
	f := newRelayFixture(t)
	subs := filepath.Join(f.options.Layout.BotDataDir(), "wdtt", "subs.json")
	f.write(t, subs, `{"tok-7":{"uid":"7","created":"x","last_hash":"h"},"tok-8":{"uid":"8","created":"y"}}`)

	changes, err := f.options.rotateSubscriptionTokens(&transaction.Manager{}, transaction.Receipt{}, map[string]bool{"7": true})
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes = %d, %v", len(changes), err)
	}
	var registry map[string]map[string]string
	if err := json.Unmarshal(changes[0].Data, &registry); err != nil {
		t.Fatal(err)
	}
	if _, kept := registry["tok-7"]; kept || registry["tok-8"] == nil || len(registry) != 2 {
		t.Errorf("registry = %v", registry)
	}
	for token, entry := range registry {
		if entry["uid"] == "7" && (token == "tok-7" || entry["last_hash"] != "") {
			t.Errorf("the new token carries the old state: %s %v", token, entry)
		}
	}
}

func TestSubscriptionTokenRotationToleratesNoRegistryOrNoOwner(t *testing.T) {
	f := newRelayFixture(t)
	users := map[string]bool{"7": true}
	if changes, err := f.options.rotateSubscriptionTokens(&transaction.Manager{}, transaction.Receipt{}, users); err != nil || changes != nil {
		t.Errorf("no registry: %v, %v", changes, err)
	}
	subs := filepath.Join(f.options.Layout.BotDataDir(), "wdtt", "subs.json")
	f.write(t, subs, `{"tok-8":{"uid":"8"}}`)
	if changes, err := f.options.rotateSubscriptionTokens(&transaction.Manager{}, transaction.Receipt{}, users); err != nil || changes != nil {
		t.Errorf("no owner: %v, %v", changes, err)
	}
}

func TestSubscriptionTokenRotationRefusesAnUnreadableRegistry(t *testing.T) {
	f := newRelayFixture(t)
	subs := filepath.Join(f.options.Layout.BotDataDir(), "wdtt", "subs.json")
	users := map[string]bool{"7": true}
	for name, content := range map[string]string{"not json": "{", "uid not a string": `{"t":{"uid":7}}`} {
		f.write(t, subs, content)
		if _, err := f.options.rotateSubscriptionTokens(&transaction.Manager{}, transaction.Receipt{}, users); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	os.Remove(subs)
	if err := os.Mkdir(subs, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := f.options.rotateSubscriptionTokens(&transaction.Manager{}, transaction.Receipt{}, users); err == nil || !strings.Contains(err.Error(), "read the subscription registry") {
		t.Errorf("directory: %v", err)
	}
}
