#!/usr/bin/env bash
# leakscan.sh — fail if any value from a private denylist appears in the tree.
#
# The denylist (one literal per line) is produced outside this repository from
# a real deployment: its keys, passwords, IDs, hosts and addresses. This script
# knows none of them; it only reports where they occur, masking each match so
# the report itself does not repeat the secret.
#
#   scripts/leakscan.sh [DENYLIST] [DIR]
#
# DENYLIST defaults to $SPAITER_VPN_DENYLIST or
# ~/.config/spaiter-vpn-leakscan/denylist. DIR defaults to what would be
# published: the index (stage first) through `git archive`, which honours the
# export-ignore paths in .gitattributes. Exit 0 clean, 1 leaks found, 2 cannot scan.
set -euo pipefail

denylist=${1:-${SPAITER_VPN_DENYLIST:-$HOME/.config/spaiter-vpn-leakscan/denylist}}
dir=${2:-}

if [[ ! -s $denylist ]]; then
	echo "leakscan: no denylist at $denylist" >&2
	exit 2
fi
command -v rg >/dev/null || { echo "leakscan: ripgrep (rg) is required" >&2; exit 2; }

mask() {
	# keep the first two characters, hide the rest
	awk -F: '{ v=$0; sub(/^[^:]*:[^:]*:/, "", v); print $1 ":" $2 ": " substr($3, 1, 2) "…(" length($3) ")" }'
}

if [[ -n $dir ]]; then
	hits=$(rg --no-config -F -f "$denylist" -o -n --hidden --no-ignore -g '!.git' "$dir" || true)
else
	export_dir=$(mktemp -d)
	trap 'rm -rf "$export_dir"' EXIT
	root=$(git rev-parse --show-toplevel)
	git -C "$root" archive "$(git -C "$root" write-tree)" | tar -x -C "$export_dir"
	hits=$(cd "$export_dir" && rg --no-config -F -f "$denylist" -o -n -H -a --hidden --no-ignore . || true)
fi

if [[ -z $hits ]]; then
	echo "leakscan: clean ($(wc -l < "$denylist") values checked)"
	exit 0
fi
printf '%s\n' "$hits" | mask | sort -u
echo "leakscan: $(printf '%s\n' "$hits" | wc -l) match(es) in $(printf '%s\n' "$hits" | cut -d: -f1 | sort -u | wc -l) file(s)" >&2
exit 1
