#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail

FC_TOOLS_DIR=$(dirname $(realpath $0))
FC_ROOT_DIR=$FC_TOOLS_DIR/..


if [ $# -ne 2 ]; then
    cat <<EOF
Compose the text for a new release using the information in the changelog,
between the two specified releases.

$0 <previous_version> <version>

    Example: $0 1.1.1 1.1.2
EOF
    exit 1;
fi

prev_ver="$1"
curr_ver="$2"
changelog="$FC_ROOT_DIR/CHANGELOG.md"

if [[ ! $prev_ver < $curr_ver ]]; then
    echo "$prev_ver >= $curr_ver. Did you switch the argument order?"
    exit 1
fi

# Patterns for the sections in the changelog corresponding to the versions.
pat_curr="^##\s\[$curr_ver\]"
pat_prev="^##\s\[$prev_ver\]"
# Extract the section enclosed between the 2 headers and strip off the first
# 2 and last 2 lines (one is blank and one contains the header `## [A.B.C]`).
# Then, replace `-` with `*` and remove section headers.
sed "/$pat_curr/,/$pat_prev/!d" "$changelog" \
    | sed '1,2d;$d' \
    | sed "s/^-/*/g" \
    | sed "s/^###\s//g"
