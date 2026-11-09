module wg-turn-client

go 1.27.0

// MPTCP only where tcp_multi_path asks for it. Go 1.24+ listens on Multipath
// TCP by default on Linux, and CVE-2026-98432 let a remote root listen on IPv4
// MPTCP. A go.mod directive reaches every build of this module; the
// -X internal/godebug.defaultGODEBUG link flag the build carried before named
// a symbol that does not exist and did nothing, which is how the production
// core listened on MPTCP (found 2026-11-06).
godebug multipathtcp=0

require (
	github.com/pion/dtls/v3 v3.1.4
	github.com/pion/transport/v4 v4.1.3
	golang.org/x/crypto v0.58.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
)

require (
	github.com/pion/logging v0.2.4 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
