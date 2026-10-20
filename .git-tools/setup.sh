#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel)

for hook in "$script_dir"/hooks/*; do
    [ -f "$hook" ] || continue
    chmod +x "$hook"
done

# Keep Git path matching case-sensitive inside this repository.
# This is important on Windows/macOS when files differ only by case.
git -C "$repo_root" config --local core.ignorecase false
git -C "$repo_root" config --local core.hooksPath '.git-tools/hooks'

printf 'Repository [%s] configured.\n' "$repo_root"
printf '%s\n' 'core.ignorecase = false' 'core.hooksPath = .git-tools/hooks'
