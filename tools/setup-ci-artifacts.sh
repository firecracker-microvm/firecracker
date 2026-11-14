#!/bin/bash
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

TOOLS_DIR=$(dirname $0)
source "$TOOLS_DIR/functions"

say "Setup CI artifacts"
cd "$1"

say "Generate SSH key to connect from host"
if [ ! -s id_rsa ]; then
    ssh-keygen -t rsa -b 2048 -f id_rsa -N ""
fi

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT

for SQUASHFS in *.squashfs
do
    [ -f "$SQUASHFS" ] || continue
    say "Include SSH key in $SQUASHFS"
    RSA="${SQUASHFS%.squashfs}.id_rsa"
    EXT4="${SQUASHFS%.squashfs}.ext4"
    unsquashfs -d "$workdir/rootfs" "$SQUASHFS"
    mkdir -pv "$workdir/rootfs/root/.ssh"
    if [ ! -s "$RSA" ]
    then
        cp -v id_rsa "$RSA"
    fi
    # Always inject the public key matching this image's private key. An
    # existing ".orig" file does not mean a newly downloaded image is staged.
    ssh-keygen -y -P "" -f "$RSA" > "$workdir/rootfs/root/.ssh/authorized_keys"
    chmod 700 "$workdir/rootfs/root/.ssh"
    chmod 600 "$workdir/rootfs/root/.ssh/authorized_keys"
    mksquashfs "$workdir/rootfs" "$workdir/rootfs.squashfs" \
        -all-root -noappend -comp zstd

    # Refresh the writable image from the same keyed rootfs.
    say "Converting $SQUASHFS to $EXT4"
    truncate -s 500M "$workdir/rootfs.ext4"
    mkfs.ext4 -F "$workdir/rootfs.ext4" -d "$workdir/rootfs"
    [ -s "$SQUASHFS.orig" ] || cp -v "$SQUASHFS" "$SQUASHFS.orig"
    mv -v "$workdir/rootfs.squashfs" "$SQUASHFS"
    mv -v "$workdir/rootfs.ext4" "$EXT4"
    rm -rf -- "$workdir/rootfs"
done

say "Uncompress debuginfo files"
find . -name "*.debug.gz" -print0 | xargs -r -P4 -0 -t -n1 gunzip
