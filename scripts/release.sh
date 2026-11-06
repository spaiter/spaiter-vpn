#!/usr/bin/env bash
#
# Build, hash and sign a spaiter-vpn release.
#
# This is a BUILD-time script, run on a machine you already trust. It is
# deliberately not an install script, and the project deliberately ships no
# `curl … | bash`: teaching the operator of a VPN server to pipe a remote
# script into root is how such a project becomes the supply-chain attack it was
# meant to protect against. The install path is: download, verify the signature,
# then run the binary yourself.
#
# Usage:
#   scripts/release.sh v0.1.0            build, hash, sign
#   scripts/release.sh v0.1.0 --source   also produce a source tarball
#   scripts/release.sh --verify DIR      check an existing release
#   scripts/release.sh --verify DIR --allow-unsigned
set -euo pipefail

readonly MODULE="github.com/spaiter/spaiter-vpn"
readonly SIGNING_KEY="C0718B337F6155B7"
readonly SIGNING_PASS_ENTRY="services/spaiter-vpn-release-signing-pass"
# amd64 only, matching the core image. Adding arm64 means building the core for
# it too, or the installer would pull an image it cannot run.
# Named TARGET_* rather than GOOS/GOARCH: those are the names `go build` reads
# from the environment, and declaring them readonly here makes the
# `GOOS=… go build` prefix below fail with "readonly variable".
readonly TARGET_OS=linux
readonly TARGET_ARCH=amd64

repo_root() { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; }

die() { printf 'release: %s\n' "$*" >&2; exit 1; }
say() { printf 'release: %s\n' "$*"; }

verify_release() {
	local dir=$1
	local allow_unsigned=${2:-}
	[[ -d $dir ]] || die "no such directory: $dir"
	cd "$dir"
	[[ -f SHA256SUMS ]] || die "no SHA256SUMS in $dir"

	# Signature first. Checking hashes before the signature is pointless: an
	# attacker who can replace a tarball can replace its hash alongside it, so
	# the hashes only mean anything once the manifest carrying them is known to
	# be authentic.
	#
	# A MISSING signature is a failure, not a warning. Stripping the .asc is
	# the cheapest possible attack, and a verifier that answers "ok" to it —
	# however loudly it grumbles to stderr — has handed the attacker the
	# result they wanted. --allow-unsigned exists for deliberately unsigned
	# local builds and says so in the exit status.
	if [[ -f SHA256SUMS.asc ]]; then
		say "verifying the signature over SHA256SUMS"
		gpg --verify SHA256SUMS.asc SHA256SUMS || die "the signature over SHA256SUMS is not valid"
	elif [[ $allow_unsigned == --allow-unsigned ]]; then
		printf 'release: WARNING: no signature, and --allow-unsigned was given; the hashes below prove integrity in transit, not authenticity\n' >&2
	else
		die "no SHA256SUMS.asc: this release is unsigned, so the hashes prove nothing about where it came from. Pass --allow-unsigned if that is deliberate"
	fi

	say "verifying the hashes"
	sha256sum --check --strict SHA256SUMS
	say "ok"
}

main() {
	if [[ ${1:-} == --verify ]]; then
		verify_release "${2:?--verify needs a directory}" "${3:-}"
		return
	fi

	local version=${1:?usage: release.sh vX.Y.Z [--source]}
	local with_source=${2:-}
	[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
		die "version must look like v1.2.3 or v1.2.3-rc1, got '$version'"

	local root; root=$(repo_root)
	cd "$root"

	# A release built from a dirty tree cannot be reproduced from the commit it
	# claims to come from, and the whole point of signing it is that someone
	# can check what they have against what was built.
	if [[ -n $(git status --porcelain) ]]; then
		die "the working tree is dirty; commit or stash before building a release"
	fi
	local commit; commit=$(git rev-parse HEAD)
	local short; short=$(git rev-parse --short=8 HEAD)

	local name="spaiter-vpn-${version}-${TARGET_OS}-${TARGET_ARCH}"
	local out="$root/dist/$version"
	rm -rf "$out"
	mkdir -p "$out/$name"

	say "building $name from $short"
	# CGO off so the binary is static and runs on any glibc or musl host;
	# -trimpath so no local path from this machine ends up in it, which also
	# keeps the build reproducible across checkout locations; -buildid= and
	# -s -w to strip what varies or bloats.
	CGO_ENABLED=0 GOOS=$TARGET_OS GOARCH=$TARGET_ARCH go build \
		-trimpath \
		-ldflags "-s -w -buildid= -X ${MODULE}/internal/cli.Version=${version}+${short}" \
		-o "$out/$name/spaiter-vpn" \
		./cmd/spaiter-vpn

	# GPL-3.0 travels with the binary, and the notices file records every
	# upstream and the one licence clause that restricts naming.
	cp LICENSE THIRD-PARTY-NOTICES.md README.md "$out/$name/"
	write_release_notes "$out/$name/RELEASE.md" "$version" "$commit"

	say "packing"
	# --sort=name, a fixed mtime, and numeric owner 0 so that building the same
	# commit twice produces the same bytes rather than embedding this machine's
	# uid and the moment of packing.
	tar --sort=name \
		--mtime="@$(git show -s --format=%ct HEAD)" \
		--owner=0 --group=0 --numeric-owner \
		-C "$out" -czf "$out/$name.tar.gz" "$name"
	rm -rf "$out/$name"

	if [[ $with_source == --source ]]; then
		say "packing the source"
		# git archive of the exact commit. Submodules are NOT included: they
		# are separate works with their own repositories, and the notices file
		# says where each lives.
		git archive --format=tar.gz --prefix="spaiter-vpn-${version}/" \
			-o "$out/spaiter-vpn-${version}-source.tar.gz" HEAD
		# The tarball must build on its own. A working tree can carry files
		# git does not: v0.1.0 to v0.1.2 shipped source missing an embedded
		# directory that a blanket ignore rule had kept out of the repository,
		# and nothing noticed because the checkout the binaries were built
		# from had the files on disk.
		say "building from the source tarball"
		local scratch; scratch=$(mktemp -d)
		tar -xzf "$out/spaiter-vpn-${version}-source.tar.gz" -C "$scratch"
		(cd "$scratch/spaiter-vpn-${version}" &&
			CGO_ENABLED=0 go build -o /dev/null ./cmd/spaiter-vpn) ||
			die "the source tarball does not build; the repository is missing something the working tree has"
		rm -rf "$scratch"
	fi

	cd "$out"
	say "hashing"
	sha256sum -- *.tar.gz > SHA256SUMS

	# Sign the manifest, not each tarball: one signature covers every artifact
	# through its hash, and there is then only one thing to verify.
	if pass show "$SIGNING_PASS_ENTRY" >/dev/null 2>&1; then
		say "signing SHA256SUMS with $SIGNING_KEY"
		pass show "$SIGNING_PASS_ENTRY" | head -1 |
			gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
				--local-user "$SIGNING_KEY" \
				--armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
	else
		printf 'release: WARNING: %s is not in pass; the release is UNSIGNED\n' "$SIGNING_PASS_ENTRY" >&2
	fi

	say "verifying what was just built"
	# --allow-unsigned here only matters when pass had no entry and the build
	# already warned; a signed build still verifies its signature.
	verify_release "$out" --allow-unsigned

	printf '\n'
	ls -la "$out"
	printf '\nrelease: %s is in %s\n' "$version" "$out"
}

write_release_notes() {
	local path=$1 version=$2 commit=$3
	cat > "$path" <<NOTES
# spaiter-vpn ${version}

Built from commit ${commit}.

## License and corresponding source

spaiter-vpn is **GPL-3.0-or-later**. The binary links the VPN core (a sing-box
fork) and the GPL libraries it depends on, so whoever redistributes it must
also make the corresponding source available (GPL-3.0 §6). That source is
public: <https://github.com/spaiter/spaiter-vpn>, commit \`${commit}\`, and the
same release ships \`spaiter-vpn-${version}-source.tar.gz\` when built with
\`scripts/release.sh ${version} --source\`. The core image carries
\`org.opencontainers.image.source\` and \`.revision\` pointing at that commit.
Third-party licenses are listed in \`THIRD-PARTY-NOTICES.md\` next to this file.

## Verify before running

    gpg --verify SHA256SUMS.asc SHA256SUMS
    sha256sum --check --strict SHA256SUMS

Check the signature **first**. Hashes alone only prove the file survived the
copy; anyone who can replace the tarball can replace its hash next to it.

Signing key: \`6D4841065CBDB46F500A4367C0718B337F6155B7\`
(\`spaiter-vpn releases\`). This is a dedicated key — deliberately **not** the
key the password store is encrypted to.

There is no install script, and that is on purpose. A one-line
\`curl … | bash\` for a VPN server teaches its operators to pipe a remote
script into root, which is exactly how such a project becomes the
supply-chain vector it exists to avoid. Unpack it and run the binary.

## Use

    ./spaiter-vpn preflight                 # check the host first
    ./spaiter-vpn init -users alice,bob
    ./spaiter-vpn up
    ./spaiter-vpn selftest

## Licensing

GPL-3.0-or-later; see LICENSE. Every upstream component and its licence is in
THIRD-PARTY-NOTICES.md — including the clause beyond GPL-3.0 that forbids
derivative works from using the name of the core this derives from.
NOTES
}

main "$@"
