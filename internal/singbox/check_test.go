package singbox

import "testing"

// TestDockerDidNotRunSeparatesRegistryFailuresFromRejections guards the
// distinction the whole package is built on. Moving the core to a private
// registry introduced a new way for `docker run` to exit non-zero without ever
// reading the config, and reporting that as "the config was rejected" sends an
// operator to debug a file that was never opened.
//
// The negative cases matter more than the positive ones: a real sing-box
// rejection must never be reclassified as a registry problem, because that
// hides the failure behind an excuse.
func TestDockerDidNotRunSeparatesRegistryFailuresFromRejections(t *testing.T) {
	didNotRun := map[string]string{
		"pull access denied":     "docker: Error response from daemon: pull access denied for registry.example.com/spaiter/spaiter-vpn-core, repository does not exist or may require 'docker login'",
		"unauthorized":           "Unable to find image 'registry.example.com/spaiter/spaiter-vpn-core:95c4dcb7' locally\ndocker: Error response from daemon: unauthorized: authentication required",
		"missing tag":            "docker: Error response from daemon: manifest unknown",
		"untrusted TLS":          `docker: Error response from daemon: Get "https://registry.example.com/v2/": x509: certificate signed by unknown authority`,
		"registry down":          `Unable to find image 'x' locally` + "\n" + `docker: Error response from daemon: Get "https://registry.example.com/v2/": dial tcp 127.0.0.1:10866: connect: connection refused`,
		"daemon down":            "docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\nError response from daemon: dial unix: connect: no such file",
		"unknown docker failure": "docker: Error response from daemon: something new and unclassified",
	}
	for name, output := range didNotRun {
		t.Run("did not run: "+name, func(t *testing.T) {
			if reason := dockerDidNotRun(output); reason == "" {
				t.Fatalf("classified as a config rejection, but the container never ran:\n%s", output)
			}
		})
	}

	// Real sing-box output. The second and third are the trap: they contain
	// exactly the words a naive classifier would key on, yet they are genuine
	// config rejections that must reach the operator as such.
	rejections := map[string]string{
		"duplicate tag":           "FATAL[0000] decode config at /etc/sing-box/config.json: duplicate inbound tag: vless-reality-in",
		"unknown field":           `FATAL[0000] decode config at /etc/sing-box/config.json: inbounds[0].nonsense_field: json: unknown field "nonsense_field"`,
		"bad shadowsocks key":     "FATAL[0000] initialize inbound[1]: bad key",
		"says connection refused": "FATAL[0000] initialize inbound[0]: reality handshake: dial tcp 1.2.3.4:443: connect: connection refused",
		"says unauthorized":       "FATAL[0000] initialize inbound[3]: upstream returned unauthorized",
		"says no such host":       "FATAL[0000] initialize inbound[0]: dial tcp: lookup example.invalid: no such host",
		"empty":                   "",
	}
	for name, output := range rejections {
		t.Run("rejection: "+name, func(t *testing.T) {
			if reason := dockerDidNotRun(output); reason != "" {
				t.Fatalf("a config rejection was misclassified as %q, which would hide the real failure:\n%s", reason, output)
			}
		})
	}
}

func TestDockerDidNotRunPrefersTheSpecificReason(t *testing.T) {
	// docker reports "Unable to find image" first and the actual cause after.
	// The generic framing must not win over the specific cause, or every
	// registry problem reads the same.
	output := "Unable to find image 'core:95c4dcb7' locally\ndocker: Error response from daemon: pull access denied for core"
	if got, want := dockerDidNotRun(output), "the registry refused the pull"; got != want {
		t.Errorf("reason is %q, want %q", got, want)
	}
}

func TestDefaultImageIsPinned(t *testing.T) {
	// A moving tag would let two runs a month apart validate against different
	// binaries while reporting the same image.
	for _, moving := range []string{":latest", ":extended", ":main", ":stable"} {
		if len(DefaultImage) > len(moving) && DefaultImage[len(DefaultImage)-len(moving):] == moving {
			t.Fatalf("DefaultImage %q ends in the moving tag %q; pin it to a commit", DefaultImage, moving)
		}
	}
	if DefaultImageRegistry == "" {
		t.Fatal("DefaultImageRegistry is empty, so the authentication hint cannot name a host")
	}
	// The hint is only useful if it actually names the registry the image is
	// pulled from.
	if len(DefaultImage) < len(DefaultImageRegistry) || DefaultImage[:len(DefaultImageRegistry)] != DefaultImageRegistry {
		t.Errorf("DefaultImage %q is not hosted on DefaultImageRegistry %q", DefaultImage, DefaultImageRegistry)
	}
}
