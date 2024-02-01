#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail

FC_TOOLS_DIR=$(dirname $(realpath $0))
source "$FC_TOOLS_DIR/functions"
FC_ROOT_DIR=$FC_TOOLS_DIR/..

# Create a tag for the specified release.
# The tag text will be composed from the changelog contents enclosed between the
# specified release number and the previous one.
function create_local_tag {
    version="$1"
    branch="$2"

    say "Obtaining tag description for local tag v$version..."
    tag_text=$($FC_TOOLS_DIR/release-notes.py "$version")
    say "Tag description for v$version:"
    echo "$tag_text"
    # Create tag.
    git tag -a v"$version" "$branch" -m "$tag_text" || die "Could not create local tag v$version."
    say "Local tag v$version created."
}


# # # # MAIN # # # #

if [ $# -ne 1 ]; then
    cat <<EOF
$0 <version>

    Example: $0 1.1.2

    It will create a local git tag and push it to the upstream
EOF
    exit 1
fi
version=$1
validate_version "$version"

LOCAL_BRANCH=$(git rev-parse --abbrev-ref HEAD)
RELEASE_BRANCH=firecracker-v$(echo "$version" |cut -d. -f-2)
UPSTREAM=upstream
UPSTREAM_URL=$(git remote get-url $UPSTREAM)
check_local_branch_is_release_branch

# Start by creating a local tag and associate to it a description.
say "Creating local tag..."
create_local_tag "$version" "$LOCAL_BRANCH"

# pretty print a warning
function warn {
    # reset reverse yellow
    echo "$(SGR 0 7 33)$*$(SGR 0)"
}

warn "!WARNING! The next step will modify upstream: $UPSTREAM_URL by running:"
echo "    git push $UPSTREAM v$version"
echo "    git push $UPSTREAM $RELEASE_BRANCH"
get_user_confirmation || die "Cancelling tag push"
git push --atomic $UPSTREAM "v$version"
git push --atomic $UPSTREAM "$RELEASE_BRANCH"
