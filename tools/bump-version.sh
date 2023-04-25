#!/usr/bin/env bash

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail
shopt -s lastpipe

FC_TOOLS_DIR=$(dirname $(realpath $0))
source "$FC_TOOLS_DIR/functions"
FC_ROOT_DIR=$FC_TOOLS_DIR/..


if [ $# -ne 1 ]; then
    cat <<EOF
$0 <version>

    Example: $0 1.4.0-dev

    Bump Firecracker release version:
    1. Updates Cargo.toml / Cargo.lock
    2. Runs 'cargo update'
EOF
    exit 1
fi
version=$1


function check_snapshot_version {
    local version=$1
    local snap_version=$(echo $version |cut -f-2 -d. |tr . _)
    if ! grep -s FC_V${snap_version}_SNAP_VERSION src/vmm/src/version_map.rs; then
       die "I couldn't find FC_V${snap_version}_SNAP_VERSION in src/vmm/src/version_map.rs"
    fi
}

check_snapshot_version "$version"


# Get current version from the swagger spec.
prev_ver=$(get_swagger_version)

say "Updating from $prev_ver to $version ..."
# Update version in files.
files_to_change=(
    "$FC_ROOT_DIR/src/api_server/swagger/firecracker.yaml"
    "$FC_ROOT_DIR/src/firecracker/Cargo.toml"
    "$FC_ROOT_DIR/src/jailer/Cargo.toml"
    "$FC_ROOT_DIR/src/rebase-snap/Cargo.toml"
    "$FC_ROOT_DIR/src/seccompiler/Cargo.toml"
    "$FC_ROOT_DIR/src/cpu-template-helper/Cargo.toml"
)
say "Updating source files:"
for file in "${files_to_change[@]}"; do
    say "- $file"
    if [[ "$file" =~ .+\.toml$ ]]; then
        # For TOML
        sed -i "s/^version = \"$prev_ver\"/version = \"$version\"/" "$file"
    elif [[ "$file" =~ .+\.yaml$ ]]; then
        # For YAML
        sed -i "s/version: $prev_ver/version: $version/" "$file"
    else
        echo "ERROR: Unrecognized file '$file'"
        exit 1
    fi
done

# Run `cargo check` to update firecracker and jailer versions in all
# `Cargo.lock`.
# NOTE: This will break if it finds paths with spaces in them
find . -path ./build -prune -o -name Cargo.lock -print |while read -r cargo_lock; do
    say "Updating $cargo_lock ..."
    (cd "$(dirname "$cargo_lock")"; cargo check; cargo update)
done
