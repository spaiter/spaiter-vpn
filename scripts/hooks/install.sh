#!/usr/bin/env bash
#
# Git hooks are not versioned, so they live here and get linked into place.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
hooks=$(git -C "$repo" rev-parse --git-path hooks)

for hook in "$repo"/scripts/hooks/*; do
	name=$(basename "$hook")
	[[ $name == install.sh ]] && continue
	ln -sf "../../scripts/hooks/$name" "$hooks/$name"
	printf 'installed %s -> %s\n' "$name" "$hooks/$name"
done
