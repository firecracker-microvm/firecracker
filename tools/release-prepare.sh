#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail

FC_TOOLS_DIR=$(dirname $(realpath $0))
source "$FC_TOOLS_DIR/functions"
FC_ROOT_DIR=$FC_TOOLS_DIR/..

if [ $# -ne 1 ]; then
    cat <<EOF
$0 <version>

    Example: $0 0.42.0

    Prepare a new Firecracker release:
    1. Update the version number
    2. Update Crate dependencies
    3. Generate CREDITS.md and CHANGELOG.md
    4. Commit the result
    5. Create a link to PR the changes
EOF
    exit 1
fi
version=$1
validate_version "$version"

check_local_branch_is_release_branch

# Create GitHub PR link
ORIGIN_URL=$(git config --get remote.origin.url)
GH_USER=$(git config --get github.user)
REPO=$(basename "$ORIGIN_URL" .git)
LOCAL_BRANCH=$(git rev-parse --abbrev-ref HEAD)
RELEASE_BRANCH=firecracker-v$(echo "$version" |cut -d. -f-2)
UPSTREAM=upstream
# In which branch should the change go, in the main repo?
TARGET_BRANCH=main
PATCH=$(echo "$version" |cut -d. -f3)
# If this is a patch release, the target branch should be the release branch
if [ "$PATCH" -gt 0 ]; then
    TARGET_BRANCH=$RELEASE_BRANCH
fi
PR_URL="https://github.com/firecracker-microvm/$REPO/compare/$TARGET_BRANCH...$GH_USER:$REPO:$LOCAL_BRANCH?expand=1"

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
)
say "Updating source files:"
for file in "${files_to_change[@]}"; do
    say "- $file"
    # Dirty hack to make this work on both macOS/BSD and Linux.
    # FIXME This is very hacky and can unintentionally bump other versions, so
    # only do the replacement *once*.
    sed -i "s/$prev_ver/$version/" "$file"
done

# Run `cargo check` to update firecracker and jailer versions in
# `Cargo.lock`.
say "Updating lockfile..."
cargo check
CHANGED=(Cargo.lock)

cd tests/integration_tests/security/demo_seccomp
cargo check
cd -
CHANGED+=(tests/integration_tests/security/demo_seccomp/Cargo.lock)

# Update credits.
say "Updating credits..."
$FC_TOOLS_DIR/update-credits.sh
CHANGED+=(CREDITS.md)

# Update changelog.
say "Updating changelog..."
sed -i "s/\[Unreleased\]/\[$version\]/g" "$FC_ROOT_DIR/CHANGELOG.md"
CHANGED+=(CHANGELOG.md)

git add "${files_to_change[@]}" "${CHANGED[@]}"
git commit -s -m "Releasing v$version"


# pretty print code
function pp-code {
    # grey background
    echo "$(SGR 0 48 5 242)$*$(SGR 0)"
}

# pretty print a list item
function pp-li {
    bullet=$1; shift
    # reset bg-color-5 bold
    echo "$(SGR 0 48 5 101)$bullet$(SGR 0 1) $*$(SGR 0)"
}

cat <<EOF
🎉 Almost done!

$(pp-li 1. Check the changes made to the repo:)

   $(pp-code git log --patch HEAD~1..HEAD)

$(pp-li 2. Preview the release notes)

   $(pp-code ./tools/release-notes.sh "$prev_ver" "$version")

$(pp-li 3. If you want to undo the changes, run)

   $(pp-code git reset --keep HEAD~1)

$(pp-li 4. Review and merge this change)

   $(pp-code git push --force -u origin HEAD)
   $PR_URL

$(pp-li 5. Once it is reviewed and merged, run the tag script)
   $(pp-code ./tools/release-tag.sh $prev_ver $version)
EOF
