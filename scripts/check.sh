#!/usr/bin/env bash
#
# The fast signal an agent (or a human) should get before committing. Five
# gates, cheapest first. Nothing here needs network or privileges.
#
# The `bot` gate (bot.py parses) and the Python half of `contract` went away on
# 2026-11-03 with the bot they checked. Both halves ran side by side through the
# port so two independent implementations of the generators were compared on
# every commit; with one implementation left there is nothing to compare.
#
#   scripts/check.sh                            all of them
#   scripts/check.sh fmt|deps|leaks|vet|test    just one
#
#   leaks   The publication gate (scripts/leakscan.sh): what `git archive`
#           would publish must carry no literal of the real deployment. The
#           denylist lives only on that deployment's host, so elsewhere the
#           gate skips and says so -- a skip is not a pass, and `check: ok`
#           on another machine does not vouch for publication.
#
# Why each gate is scoped the way it is:
#
#   gofmt   Every tracked .go file except two deliberately unformatted zones
#           (FMT_EXCLUDE below). It was limited to changed files until a471a9d
#           formatted the 526 files the monorepo path rewrite had left
#           unsorted; before that a tree-wide gate would have failed on every
#           run and taught everyone to ignore it.
#
#   vet     First-party packages only. core/replace/ holds forked upstream
#           whose tests were written against other module paths and do not
#           compile -- and a vet failure there aborts the whole run, hiding
#           every finding after it. That is exactly how the broken tlsspoof
#           and geosite tests stayed invisible. Known-accepted findings live
#           in scripts/vet-baseline.txt; the gate fails only on new ones.
#
#   deps    The root go.mod pins 781 modules of the sing-box fork, and the
#           binary built from them is what the deployment runs. A dependency
#           that drags in its own transitives moves that graph quietly, and
#           core/PROVENANCE.md forbids a casual `go mod tidy` for the same
#           reason. So any change to go.mod or go.sum has to be accompanied by
#           a note in PROVENANCE.md and a refreshed digest, which is what makes
#           the move deliberate rather than incidental.
#
#   test    Needs -checklinkname=0: experimental/libbox reaches into
#           runtime/pprof internals via //go:linkname, so without the flag it
#           fails to link ("invalid reference to parseProcSelfMaps"). See
#           core/PROVENANCE.md on that layer. common/netns is skipped because
#           its tests fork /proc/self/exe and need privileges.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

readonly BASELINE=scripts/vet-baseline.txt
readonly DEPS_BASELINE=scripts/deps-baseline.txt
rc=0

say() { printf '\n== %s\n' "$*"; }

# relay/ is its own Go module, so it cannot be listed from the root one.
#
# internal/ and cmd/ were missing here until 2026-11-02, which left the
# installer -- 15 packages with 15 test files -- outside both vet and test. The
# first run after adding them found a test that hardcoded a port inside
# ip_local_port_range.
first_party_packages() {
	go list ./internal/... ./cmd/... 2>/dev/null
}

# core/ is its own module (github.com/sagernet/sing-box, reached from the root by
# replace), so its packages are listed, vetted and tested from inside it, with the
# build tags its own Makefile uses -- upstream's tests are written for them, and
# several do not compile without. core/replace/ holds the forks, whose tests
# target other module paths.
# core_go <go-subcommand> [flags...]: run it on every core package, with the tags.
core_go() {
	local sub=$1
	shift
	(cd core && tags=$(sed -n 's/^TAGS ?= //p' Makefile) &&
		go list -tags "$tags" -f '{{if or .GoFiles .TestGoFiles}}{{.ImportPath}}{{end}}' ./... 2>/dev/null |
		grep -v '/replace/' | xargs -r go "$sub" -tags "$tags" "$@")
}

# Zones held unformatted on purpose, each for a reason recorded in the repo:
#
#   core/replace/      forks of upstream libraries (hiddify's and ours), kept textually
#                      close to their origins so they rebase cleanly, see
#                      core/PROVENANCE.md.
#   core/ files that hiddify writes unformatted and we do not touch (new ones
#                      appear on every rebase; list them when the gate names them)
#   relay/server.go    the WDTT codec, reused verbatim from kostfuciy/qWDTT so
#                      stock clients stay wire-compatible, see relay/NOTICE.md.
#
# Drift inside them is reported but does not fail the gate.
readonly FMT_EXCLUDE=(
	'^core/replace/'
	'^core/hiddify/warpscan/'
	'^core/transport/v2raykcp/kcp/connection_test\.go$'
	'^core/experimental/cachefile/h_dns_cache_flush_test\.go$'
	'^core/h_warp_detour_live_test\.go$'
	'^relay/server\.go$'
)

fmt_files() {
	local list
	# --others --exclude-standard so a brand new file is checked too: tracked
	# files alone would let an agent's first commit of a file slip through.
	list=$(git ls-files --cached --others --exclude-standard '*.go')
	local pattern
	for pattern in "${FMT_EXCLUDE[@]}"; do
		list=$(printf '%s\n' "$list" | grep -vE "$pattern")
	done
	printf '%s\n' "$list"
}

gate_fmt() {
	say "gofmt (whole tree)"
	local files unformatted excluded
	files=$(fmt_files)
	unformatted=$(printf '%s\n' "$files" | xargs -r gofmt -l)
	if [[ -n $unformatted ]]; then
		echo "$unformatted" | sed 's/^/  needs gofmt: /'
		echo "fix with: gofmt -w $(echo "$unformatted" | tr '\n' ' ')"
		return 1
	fi
	excluded=$(git ls-files '*.go' | grep -E "$(
		IFS='|'
		echo "${FMT_EXCLUDE[*]}"
	)" | xargs -r gofmt -l | wc -l)
	printf '%s file(s) clean, %s excluded file(s) unformatted (expected)\n' \
		"$(printf '%s\n' "$files" | wc -l)" "$excluded"
}

# Needs both cores -- two because their option schemas differ and a config
# checked against the wrong one is worse than unchecked. The binaries are built
# into .cache/ on demand (about 5s each once the Go cache is warm) unless
# SING_BOX_BIN / SING_BOX_CLIENT_BIN point somewhere already.
#
# The client core lives outside this repository and is host-specific, so its
# absence would be a skip -- which is why CONTRACT_REQUIRED is set below. A gate
# that reports success for checks which never ran is worse than a red one.
readonly CACHE=.cache
readonly SERVER_TAGS="with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_masque,with_awg,badlinkname,tfogo_checklinkname0"
readonly CLIENT_TAGS="with_quic,with_utls,with_clash_api,with_wireguard,with_awg,badlinkname,tfogo_checklinkname0"

# build_core <output> <tags> <module-dir> <main-package>
# The output path is made absolute before the subshell changes directory, and
# the main package is explicit: it is ./core/cmd/sing-box here and
# ./cmd/sing-box in the client tree.
build_core() {
	local out=$1 tags=$2 dir=$3 pkg=$4
	mkdir -p "$(dirname "$out")"
	local abs
	abs=$(cd "$(dirname "$out")" && pwd)/$(basename "$out")
	(
		cd "$dir" &&
			GOTOOLCHAIN=local CGO_ENABLED=0 go build -tags "$tags" \
				-ldflags '-checklinkname=0' -o "$abs" "$pkg"
	)
}

# absolute leaves a path alone if it already is, since SING_BOX_BIN may be set
# to one and prefixing it would produce nonsense.
absolute() {
	case $1 in
	/*) printf '%s\n' "$1" ;;
	*) printf '%s/%s\n' "$PWD" "$1" ;;
	esac
}

gate_contract() {
	say "bot <-> core contract"
	local client_src=${CLIENT_CORE_SRC:-$HOME/src/proxy-vpn-client-lab/sing-box}

	local server=${SING_BOX_BIN:-}
	if [[ -z $server ]]; then
		server=$CACHE/sing-box-server
		build_core "$server" "$SERVER_TAGS" . github.com/sagernet/sing-box/cmd/sing-box || {
			echo "server core failed to build"
			return 1
		}
	fi

	local client=${SING_BOX_CLIENT_BIN:-}
	if [[ -z $client ]]; then
		if [[ ! -d $client_src/cmd/sing-box ]]; then
			echo "skipped: no client core at $client_src"
			return 0
		fi
		client=$CACHE/sing-box-client
		build_core "$client" "$CLIENT_TAGS" "$client_src" ./cmd/sing-box || {
			echo "client core failed to build"
			return 1
		}
	fi

	# Absolute either way: the test runs in the package directory, where a path
	# relative to the repository root means something else entirely.
	local go_env=(CONTRACT_REQUIRED=1)
	[[ -n $server ]] && go_env+=("SING_BOX_BIN=$(absolute "$server")")
	[[ -n $client ]] && go_env+=("SING_BOX_CLIENT_BIN=$(absolute "$client")")
	local go_out
	go_out=$(env "${go_env[@]}" go test -count=1 -run TestContract \
		./internal/bot/clientcfg/ 2>&1)
	local go_rc=$?
	if [[ $go_rc -ne 0 ]]; then
		echo "$go_out"
	else
		echo "$(env "${go_env[@]}" go test -count=1 -v -run TestContract \
			./internal/bot/clientcfg/ 2>&1 | grep -cE '^\s*--- PASS') checks pass"
	fi

	return $go_rc
}

gate_vet() {
	say "go vet (first-party + relay module)"
	local found
	found=$({
		first_party_packages | xargs -r go vet 2>&1
		# paths printed inside core/ are made relative to the repository root
		core_go vet 2>&1 | sed -E 's#^(vet: )?([A-Za-z0-9_./-]+\.go:)#\1core/\2#'
		(cd relay && go vet ./... 2>&1)
	} | grep -vE '^#|^go: (downloading|finding|found)' | sort -u)
	if [[ ! -f $BASELINE ]]; then
		echo "$found" > "$BASELINE"
		echo "wrote new baseline to $BASELINE"
		return 0
	fi
	local new
	new=$(comm -13 "$BASELINE" <(echo "$found"))
	if [[ -n $new ]]; then
		echo "$new" | sed 's/^/  NEW: /'
		echo "if these are acceptable, add them to $BASELINE"
		return 1
	fi
	echo "no findings beyond the $(grep -c . "$BASELINE") baselined one(s)"
}

# gate_deps guards the module graph.
#
# The digest covers go.mod and go.sum together: a go.sum line without a go.mod
# one is a transitive that appeared, which is the thing worth noticing.
gate_deps() {
	say "module graph"
	local digest
	digest=$(cat go.mod go.sum | sha256sum | cut -d' ' -f1)
	if [[ ! -f $DEPS_BASELINE ]]; then
		printf '%s\n' "$digest" > "$DEPS_BASELINE"
		echo "wrote new baseline to $DEPS_BASELINE"
		return 0
	fi

	local expected
	expected=$(head -1 "$DEPS_BASELINE")
	if [[ $digest == "$expected" ]]; then
		echo "unchanged ($(grep -cE '^[[:space:]]+[^/[:space:]]' go.mod) requirements)"
		return 0
	fi

	cat <<-EOF
		go.mod/go.sum changed.

		  expected $expected
		  found    $digest

		This is not a failure if the change was intended. Confirm the graph did
		not move further than the dependency you added -- \`git diff go.mod
		go.sum\` should show nothing but it and its transitives -- then record
		why in core/PROVENANCE.md and refresh the digest:

		  cat go.mod go.sum | sha256sum | cut -d' ' -f1 > $DEPS_BASELINE
	EOF
	return 1
}

gate_test() {
	say "go test (first-party, short)"
	local output status
	output=$({
		first_party_packages | xargs -r go test -short -count=1 -ldflags '-checklinkname=0' 2>&1
		# netns needs privileges to fork a holder process
		(cd core && tags=$(sed -n 's/^TAGS ?= //p' Makefile) &&
			go list -tags "$tags" -f '{{if or .GoFiles .TestGoFiles}}{{.ImportPath}}{{end}}' ./... 2>/dev/null |
			grep -vE '/replace/|/common/netns$' |
			xargs -r go test -short -count=1 -tags "$tags" -ldflags '-checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=test' 2>&1)
	})
	status=$(printf '%s\n' "$output" | grep -qE '^(FAIL|--- FAIL|panic:)' && echo 1 || echo 0)
	if [[ $status -ne 0 ]]; then
		echo "$output" | grep -vE '^(ok|---)|no test files'
		return 1
	fi
	echo "all packages pass"
}

# gate_leaks fails if what would be published carries a value of the real
# deployment. It needs that deployment's denylist, which only its host has, so
# without one (or without ripgrep, which leakscan.sh needs) it is skipped
# rather than passed. Part of `all` since 2026-11-06, when the default core
# image moved to GHCR and the last known match went away.
gate_leaks() {
	say "leaks (published tree)"
	local list=${SPAITER_VPN_DENYLIST:-$HOME/.config/spaiter-vpn-leakscan/denylist}
	if [[ ! -s $list ]]; then
		echo "skipped: no denylist at $list (only the deployment host has one)"
		return 0
	fi
	if ! command -v rg >/dev/null; then
		echo "skipped: ripgrep (rg) not installed"
		return 0
	fi
	"$(dirname "$0")/leakscan.sh" "$list"
}

case "${1:-all}" in
fmt) gate_fmt || rc=1 ;;
vet) gate_vet || rc=1 ;;
test) gate_test || rc=1 ;;
deps) gate_deps || rc=1 ;;
contract) gate_contract || rc=1 ;;
leaks) gate_leaks || rc=1 ;;
all)
	gate_fmt || rc=1
	gate_deps || rc=1
	gate_leaks || rc=1
	gate_vet || rc=1
	gate_test || rc=1
	;;
*)
	echo "usage: scripts/check.sh [all|fmt|deps|leaks|vet|test|contract]" >&2
	exit 2
	;;
esac

if [[ $rc -ne 0 ]]; then
	printf '\ncheck: FAILED\n'
else
	printf '\ncheck: ok\n'
fi
exit $rc
