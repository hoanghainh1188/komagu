#!/bin/sh
# Apply the runbook W10-3 fixes to a copy of this app: apply-fixes.sh DIR
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
dir=$1
patch -d "$dir" -p1 -s < "$here/pilot-fixes.patch"
mkdir -p "$dir/src/main/java/dev/komagu/legacy/shim"
cp "$repo/remediate/legacy_shims/java/OwnershipEnforcer.java" "$dir/src/main/java/dev/komagu/legacy/shim/"
