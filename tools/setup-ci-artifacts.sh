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

say "Generate SSH key to connect from host"
if [ ! -s id_rsa ]; then
    ssh-keygen -f id_rsa -N ""
fi

for SQUASHFS in *.squashfs; do
    say "Include SSH key in $SQUASHFS"
    RSA=$(basename $SQUASHFS .squashfs).id_rsa
    EXT4=$(basename $SQUASHFS .squashfs).ext4
    [ -s $SQUASHFS.orig ] && continue
    unsquashfs $SQUASHFS
    mkdir -pv squashfs-root/root/.ssh
    # copy the SSH key into the rootfs
    if [ ! -s $RSA ]; then
        # append SSH key to the squashfs image
        cp -v id_rsa.pub squashfs-root/root/.ssh/authorized_keys
        cp -v id_rsa $RSA
    fi
    # re-squash
    mv -v $SQUASHFS $SQUASHFS.orig
    mksquashfs squashfs-root $SQUASHFS -all-root -noappend -comp zstd

    # Create rw ext4 image from ro squashfs
    [ -f $EXT4 ] && continue
    say "Converting $SQUASHFS to $EXT4"
    truncate -s 400M $EXT4
    mkfs.ext4 -F $EXT4 -d squashfs-root
    rm -rf squashfs-root
done

say "Uncompress debuginfo files"
find . -name "*.debug.gz" -print0 | xargs -P4 -0 -t -n1 gunzip
