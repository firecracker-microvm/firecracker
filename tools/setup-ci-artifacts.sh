#!/bin/bash
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

TOOLS_DIR=$(dirname $0)
source "$TOOLS_DIR/functions"

say "Setup CI artifacts"
cd build/img/$(uname -m)

say "Fix executable permissions"
find "firecracker" -type f |xargs chmod -c 755

say "Fix RSA key permissions"
find . -type f -name "*.id_rsa" |xargs chmod -c 400

for SQUASHFS in *.squashfs; do
    EXT4=$(basename $SQUASHFS .squashfs).ext4

    # Create rw ext4 image from ro squashfs
    [ -f $EXT4 ] && continue
    say "Converting $SQUASHFS to $EXT4"
    truncate -s 400M $EXT4
    unsquashfs $SQUASHFS
    mkfs.ext4 -F $EXT4 -d squashfs-root
    rm -rf squashfs-root
done
