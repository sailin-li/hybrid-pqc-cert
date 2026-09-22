#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gmssl_dir=${1:-"$project_dir/third_party/GmSSL"}

if [ ! -d "$gmssl_dir/.git" ] &&
   ! git -C "$gmssl_dir" rev-parse --git-dir >/dev/null 2>&1; then
    echo "not a GmSSL git worktree: $gmssl_dir" >&2
    exit 2
fi

for patch in "$project_dir"/patches/gmssl/*.patch; do
    echo "Applying $(basename -- "$patch")"
    git -C "$gmssl_dir" apply "$patch"
done
