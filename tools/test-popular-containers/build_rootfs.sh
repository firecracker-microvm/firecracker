#!/bin/bash
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail
set -x

cd $(dirname $0)
TOPDIR=$(git rev-parse --show-cdup)
source "$TOPDIR/tools/functions"

# Get the executing uid and gid for `chown` and `chgrp`
USER_UID=$(stat -c '%u' "$TOPDIR")
USER_GID=$(stat -c '%g' "$TOPDIR")

OVERLAY_DIR="$TOPDIR/resources/overlay"
SETUP_SCRIPT="setup-minimal.sh"
OUTPUT_DIR=$PWD

IMAGES=(amazonlinux:2023 alpine:latest ubuntu:22.04 ubuntu:24.04 ubuntu:25.04 ubuntu:latest)

# Generate SSH key for access from host
if [ ! -s id_rsa ]; then
  ssh-keygen -f id_rsa -N ""
fi

# install rootfs dependencies
apt update
apt install -y busybox-static cpio curl docker.io tree
prepare_docker

for img in "${IMAGES[@]}"; do
  build_rootfs "$img" "$OUTPUT_DIR" "$OVERLAY_DIR" "$SETUP_SCRIPT"

  rootfs_name="${img//:/-}"
  cp id_rsa "$rootfs_name.id_rsa"
  chmod a+r "$rootfs_name.id_rsa"

  chown "$USER_UID":"$USER_GID" "$rootfs_name.squashfs" "$rootfs_name.id_rsa"
done
