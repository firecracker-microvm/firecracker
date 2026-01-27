#!/bin/bash
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu -o pipefail

apply_patch_file() {
  echo "Applying patch:" $(basename $1)

  git am --empty=keep < $1
}

apply_patch_or_series() {
  case "$1" in
  *.patch) apply_patch_file $1 ;;
  *) echo "Skipping non-patch file" $1 ;;
  esac
}

apply_all_patches() {
  if [ ! -d "$1" ]; then
    echo "Not a directory: $1"
    return
  fi

  echo "Applying all patches in $1"

  for f in $1/*; do
    if [ -d $f ]; then
      apply_all_patches $f
    else
      apply_patch_or_series $f
    fi
  done
}

SCRIPT_DIR="$(dirname "$0")"
KERNEL_COMMIT_HASH=$(cat "$SCRIPT_DIR"/kernel_commit_hash)
KERNEL_PATCHES_DIR="$SCRIPT_DIR"/linux_patches

HEAD_HASH="$(git rev-parse HEAD)"
if [ $? != 0 ]; then
  echo "Failed to get git revision, are you in a kernel tree?"
  exit $?
fi
if [ "$HEAD_HASH" != "$KERNEL_COMMIT_HASH" ]; then
  echo "Cowardly refusing to apply patches unless you check out $KERNEL_COMMIT_HASH"
  exit 1
fi

# Apply our patches on top
apply_all_patches $KERNEL_PATCHES_DIR
