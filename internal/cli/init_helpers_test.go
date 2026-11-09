package cli

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestParsePortAndHostPort(t *testing.T) {
	for in, want := range map[string]uint16{"1": 1, " 443 ": 443, "65535": 65535} {
		if got, err := parsePort(in); err != nil || got != want {
			t.Errorf("parsePort(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "65536", "-1", "http", "1.5"} {
		if _, err := parsePort(bad); err == nil {
			t.Errorf("parsePort(%q) was accepted", bad)
		}
	}

	host, port, err := splitHostPort("example.org", 443)
	if err != nil || host != "example.org" || port != 443 {
		t.Errorf("bare host: %s %d %v", host, port, err)
	}
	if host, port, err = splitHostPort("example.org:8443", 443); err != nil || host != "example.org" || port != 8443 {
		t.Errorf("host:port: %s %d %v", host, port, err)
	}
	for _, bad := range []string{":443", "", "h:0", "h:abc"} {
		if _, _, err := splitHostPort(bad, 443); err == nil {
			t.Errorf("splitHostPort(%q) was accepted", bad)
		}
	}
}

func TestListParsing(t *testing.T) {
	if got := splitList(" a, ,b ,,c "); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("splitList = %q", got)
	}
	if splitList("") != nil {
		t.Error("an empty list must be empty")
	}
	ids, err := parseIDList("1, -100123 ,3")
	if err != nil || !reflect.DeepEqual(ids, []int64{1, -100123, 3}) {
		t.Errorf("ids = %v, %v", ids, err)
	}
	// A non-numeric admin would silently never get the role.
	if _, err := parseIDList("1,@alice"); err == nil || !strings.Contains(err.Error(), "@alice") {
		t.Errorf("non-numeric id: %v", err)
	}
	if joinProtocols([]profile.Protocol{"a", "b"}) != "a, b" {
		t.Error("joinProtocols")
	}
}

func TestMustAbsMakesRelativePathsAbsolute(t *testing.T) {
	if got := mustAbs("x/y"); !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.Join("x", "y")) {
		t.Errorf("mustAbs = %q", got)
	}
}

func TestSpecFromFlags(t *testing.T) {
	base := func() initFlags {
		return initFlags{users: "alice, bob", tier: string(profile.TierA), xdpInterfaces: "none"}
	}

	spec, err := specFromFlags(base())
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Users) != 2 || spec.XDPInterfaces != nil {
		t.Errorf("users=%v xdp=%v", spec.Users, spec.XDPInterfaces)
	}

	f := base()
	f.users = " , "
	if _, err := specFromFlags(f); !errors.Is(err, ErrUsage) {
		t.Errorf("no users: %v (a server with no users accepts nobody)", err)
	}

	f = base()
	f.xdpInterfaces = "eth0, eth1"
	if spec, _ = specFromFlags(f); !reflect.DeepEqual(spec.XDPInterfaces, []string{"eth0", "eth1"}) {
		t.Errorf("xdp = %v", spec.XDPInterfaces)
	}

	f = base()
	f.disable = string(profile.Snell)
	spec, err = specFromFlags(f)
	if err != nil || spec.Enabled[profile.Snell] || !spec.Enabled[profile.AWG2] {
		t.Errorf("disable: %v %v", err, spec.Enabled)
	}
	for _, p := range spec.EnabledProtocols() {
		if p == profile.Snell {
			t.Error("a disabled protocol is still enabled")
		}
	}
	f.disable = "nonsense"
	if _, err := specFromFlags(f); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("unknown protocol in -disable: %v", err)
	}

	f = base()
	f.ports = string(profile.AWG2) + "=23456"
	if spec, err = specFromFlags(f); err != nil || spec.Ports[profile.AWG2] != 23456 {
		t.Errorf("ports: %v %v", err, spec.Ports[profile.AWG2])
	}
	for _, bad := range []string{"awg2", "nonsense=1", string(profile.AWG2) + "=0", string(profile.AWG2) + "=x"} {
		f.ports = bad
		if _, err := specFromFlags(f); !errors.Is(err, ErrUsage) {
			t.Errorf("-ports %q: %v", bad, err)
		}
	}

	f = base()
	f.realityTarget, f.shadowTLSTarget, f.mtprotoFront, f.logLevel = "r.example:8443", "s.example", "front.example", "debug"
	spec, err = specFromFlags(f)
	if err != nil {
		t.Fatal(err)
	}
	if spec.RealityHandshakeServer != "r.example" || spec.RealityHandshakePort != 8443 ||
		spec.ShadowTLSHandshakeServer != "s.example" || spec.ShadowTLSHandshakePort != 443 ||
		spec.MTProtoFrontDomain != "front.example" || spec.LogLevel != "debug" {
		t.Errorf("spec = %+v", spec)
	}
	f.realityTarget = ":1"
	if _, err := specFromFlags(f); err == nil || !strings.Contains(err.Error(), "-reality-handshake") {
		t.Errorf("bad reality target: %v", err)
	}
	f = base()
	f.shadowTLSTarget = "h:0"
	if _, err := specFromFlags(f); err == nil || !strings.Contains(err.Error(), "-shadowtls-handshake") {
		t.Errorf("bad shadowtls target: %v", err)
	}
	f = base()
	f.domain = "x.example" // certificate flags in tier a
	if _, err := specFromFlags(f); !errors.Is(err, ErrUsage) {
		t.Errorf("cert flags in tier a: %v", err)
	}
}

func TestEnsureMarkerFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "reload")
	if err := ensureMarkerFile(path); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("marker: %v %v", info, err)
	}
	os.WriteFile(path, []byte("keep"), 0o640)
	if err := ensureMarkerFile(path); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Errorf("an existing marker was truncated: %q", data)
	}
	// Docker creates a directory at a missing bind source; that must be named.
	asDir := filepath.Join(dir, "dir")
	os.Mkdir(asDir, 0o755)
	if err := ensureMarkerFile(asDir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("a directory marker: %v", err)
	}
	blocked := filepath.Join(path, "child") // a file where a directory is needed
	if err := ensureMarkerFile(blocked); err == nil {
		t.Error("a marker below a regular file was created")
	}
}

func TestRenderSecretsShowsOnlyWhatIsSet(t *testing.T) {
	empty := renderSecrets(profile.Secrets{})
	if !strings.HasPrefix(empty, "=== client credentials ===") || strings.Contains(empty, "reality") || strings.Contains(empty, "---") {
		t.Errorf("empty:\n%s", empty)
	}
	var s profile.Secrets
	s.Reality.PublicKey, s.Reality.ShortID = "PUB", "SID"
	s.MTProto.Secret, s.MTProto.FrontDomain = "MTS", "front.example"
	s.Shadowsocks.Method, s.Shadowsocks.Password = "2022-blake3", "SSP"
	s.Snell.PSK, s.Snell.Version = "PSK", 5
	s.Users = []profile.UserSecrets{{
		Name: "alice", VLESSRealityUUID: "U1", VLESSWSCDNUUID: "U2", ShadowTLSPassword: "STP",
		SnellUserKey: "SK", MieruPassword: "MP",
		Peers: map[profile.Protocol]profile.PeerSecrets{
			profile.AWG2: {PrivateKey: "AWGKEY", Address: netip.MustParsePrefix("10.0.0.2/32")},
		},
	}}
	got := renderSecrets(s)
	for _, want := range []string{"PUB", "SID", "MTS (front front.example)", "2022-blake3 / SSP", "PSK (v5)",
		"--- alice ---", "U1", "U2", "STP", "SK", "MP", "10.0.0.2/32  key AWGKEY"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, string(profile.AWG3)+":") {
		t.Error("a peer the user does not have was rendered")
	}
}
