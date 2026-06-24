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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

list_variants() {
  for d in "$SCRIPT_DIR"/kernels/*/; do
    [ -d "$d" ] && basename "$d"
  done
}

# The variant is the first argument. Default to the sole variant if exactly one
# exists, otherwise require an explicit choice.
VARIANT="${1:-}"
if [ -z "$VARIANT" ]; then
  mapfile -t _variants < <(list_variants)
  if [ "${#_variants[@]}" -eq 1 ]; then
    VARIANT="${_variants[0]}"
  else
    echo "Usage: $0 <variant>" >&2
    echo "Available variants:" >&2
    list_variants | sed 's/^/  - /' >&2
    exit 1
  fi
fi

VARIANT_DIR="$SCRIPT_DIR/kernels/$VARIANT"
if [ ! -d "$VARIANT_DIR" ]; then
  echo "Unknown variant '$VARIANT'. Available variants:" >&2
  list_variants | sed 's/^/  - /' >&2
  exit 1
fi

KERNEL_COMMIT_HASH=$(cat "$VARIANT_DIR"/kernel_commit_hash)
KERNEL_PATCHES_DIR="$VARIANT_DIR"/linux_patches

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
