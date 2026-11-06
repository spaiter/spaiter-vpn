package backup

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
)

func sampleSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	s := &Snapshot{Manifest: Manifest{Hostname: "old", PublicHost: "203.0.113.7"}}
	for _, f := range []struct {
		root Root
		rel  string
		data string
	}{
		{RootConfig, DesiredPath, `{}`},
		{RootConfig, ConfigPath, `{"inbounds":[]}`},
		{RootConfig, SecretsPath, `{}`},
		{RootConfig, "credentials/telegram-token", "123:abc"},
		{RootData, "bot/wdtt/subs.json", `{"tok":{"uid":"1"}}`},
		{RootData, "cache/certmagic/acme/account.json", `{}`},
	} {
		if err := s.AddData(f.root, f.rel, 0o600, []byte(f.data)); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestRoundTripWithPassphrase(t *testing.T) {
	s := sampleSnapshot(t)
	recipient, err := age.NewScryptRecipient("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	recipient.SetWorkFactor(10)
	var buf bytes.Buffer
	if err := s.Write(&buf, recipient); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("123:abc")) {
		t.Fatal("a credential is readable in the archive")
	}

	wrong, _ := age.NewScryptIdentity("wrong")
	if _, err := Read(bytes.NewReader(buf.Bytes()), wrong); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a wrong passphrase gave %v", err)
	}
	identity, _ := age.NewScryptIdentity("correct horse")
	got, err := Read(bytes.NewReader(buf.Bytes()), identity)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.PublicHost != "203.0.113.7" || len(got.Files) != len(s.Files) {
		t.Fatalf("manifest = %+v, %d files", got.Manifest, len(got.Files))
	}
	f, ok := got.Lookup(RootConfig, "credentials/telegram-token")
	if !ok || string(f.Data) != "123:abc" || f.Mode != 0o600 {
		t.Fatalf("credential = %+v", f)
	}
}

func TestWriteRefusesNoRecipient(t *testing.T) {
	if err := sampleSnapshot(t).Write(&bytes.Buffer{}); err == nil {
		t.Fatal("an unencrypted backup was written")
	}
}

// encryptTar wraps a hand-made tar stream, to feed Read what Write never writes.
func encryptTar(t *testing.T, build func(tw *tar.Writer)) ([]byte, age.Identity) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	build(tw)
	tw.Close()
	enc.Close()
	return buf.Bytes(), identity
}

func put(tw *tar.Writer, name, data string) {
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
	tw.Write([]byte(data))
}

func TestReadRejectsWhatTheManifestDoesNotVouchFor(t *testing.T) {
	manifest := `{"format":"` + Format + `","files":[{"root":"config","path":"a","mode":384,"size":1,"sha256":"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}]}`
	cases := map[string]func(tw *tar.Writer){
		"damaged": func(tw *tar.Writer) { put(tw, manifestName, manifest); put(tw, "config/a", "b") },
		"extra": func(tw *tar.Writer) {
			put(tw, manifestName, manifest)
			put(tw, "config/a", "a")
			put(tw, "config/b", "b")
		},
		"missing": func(tw *tar.Writer) { put(tw, manifestName, manifest) },
		"unsafe": func(tw *tar.Writer) {
			put(tw, manifestName, `{"format":"`+Format+`","files":[{"root":"config","path":"../../etc/passwd","size":1}]}`)
		},
		"no manifest first": func(tw *tar.Writer) { put(tw, "config/a", "a"); put(tw, manifestName, manifest) },
	}
	for name, build := range cases {
		data, identity := encryptTar(t, build)
		if _, err := Read(bytes.NewReader(data), identity); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	data, identity := encryptTar(t, func(tw *tar.Writer) { put(tw, manifestName, manifest); put(tw, "config/a", "a") })
	if _, err := Read(bytes.NewReader(data), identity); err != nil {
		t.Errorf("a sound archive was refused: %v", err)
	}
}

func TestPlaceWritesStateAndLeavesRenderedFilesToBootstrap(t *testing.T) {
	root := t.TempDir()
	layout := discover.Layout{ConfigRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "var")}
	s := sampleSnapshot(t)
	if err := s.AddData(RootRelay, "passwords.json", 0o640, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	relay := filepath.Join(root, "relay")

	if err := CheckFresh(s, layout, relay); err != nil {
		t.Fatalf("an empty host is not fresh: %v", err)
	}
	if _, err := Place(s, layout, relay); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{layout.ConfigPath(), layout.SecretsPath(), layout.DesiredPath()} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was placed; bootstrap renders it", p)
		}
	}
	info, err := os.Stat(filepath.Join(layout.CredentialDir(), "telegram-token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential: %v %v", info, err)
	}
	if data, _ := os.ReadFile(filepath.Join(relay, "passwords.json")); string(data) != "{}" {
		t.Error("relay passwords were not placed")
	}

	// An interrupted restore leaves the same files; running again continues.
	if err := CheckFresh(s, layout, relay); err != nil {
		t.Fatalf("a re-run over its own files was refused: %v", err)
	}
	os.WriteFile(filepath.Join(layout.BotDataDir(), "wdtt", "subs.json"), []byte(`{"other":1}`), 0o600)
	if err := CheckFresh(s, layout, relay); !errors.Is(err, ErrNotFresh) {
		t.Fatalf("different bot state was going to be overwritten: %v", err)
	}
	os.MkdirAll(filepath.Dir(layout.DesiredPath()), 0o700)
	os.WriteFile(layout.DesiredPath(), []byte("{}"), 0o600)
	if err := CheckFresh(s, layout, relay); err == nil || !strings.Contains(err.Error(), "desired.json") {
		t.Fatalf("a deployed host was taken as fresh: %v", err)
	}
}
