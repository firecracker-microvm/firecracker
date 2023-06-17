#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail
shopt -s lastpipe

FC_TOOLS_DIR=$(dirname $(realpath $0))
source "$FC_TOOLS_DIR/functions"
FC_ROOT_DIR=$FC_TOOLS_DIR/..

if [ $# -ne 1 ]; then
    cat <<EOF
$0 <version>

    Example: $0 0.42.0

    Prepare a new Firecracker release:
    1. Update the version number
    2. Generate CREDITS.md and CHANGELOG.md
    3. Commit the result
    4. Create a link to PR the changes
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

# Update version
$FC_TOOLS_DIR/bump-version.sh "$version"

# Update credits.
say "Updating credits..."
$FC_TOOLS_DIR/update-credits.sh

# Update changelog.
say "Updating changelog..."
sed -i "s/\[Unreleased\]/\[$version\]/g" "$FC_ROOT_DIR/CHANGELOG.md"

# Add all changed files
git add -u
git commit -s -m "chore: release v$version"


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

   $(pp-code ./tools/release-notes.sh "$version")

$(pp-li 3. If you want to undo the changes, run)

   $(pp-code git reset --keep HEAD~1)

$(pp-li 4. Review and merge this change)

   $(pp-code git push --force -u origin HEAD)
   $PR_URL

$(pp-li 5. Once it is reviewed and merged, run the tag script)
   $(pp-code ./tools/release-tag.sh $version)
EOF
