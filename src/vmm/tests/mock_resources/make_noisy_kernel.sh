#!/bin/bash

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script illustrates the build steps for `test_noisy_elf.bin`.

set -e

WORKDIR="/tmp/noisy_kernel"
SOURCE=$(readlink -f "$0")
TEST_RESOURCE_DIR="$(dirname "$SOURCE")"
FC_DIR="$TEST_RESOURCE_DIR/../../../.."

KERNEL="linux-4.14.176"
KERNEL_ARCHIVE="$KERNEL.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v4.x/$KERNEL_ARCHIVE"

INIT_PROJ="dirtying_init"
INIT_ARCHIVE="$INIT_PROJ.tgz"

rm -rf "$WORKDIR" && mkdir -p "$WORKDIR"

# Prepare dirtying init.
echo "Preparing init..."
cp "$INIT_ARCHIVE" "$WORKDIR"
cd "$WORKDIR"
tar xzf "$INIT_ARCHIVE"
pushd "$INIT_PROJ" &>/dev/null
cargo build --release
popd &>/dev/null

# Download kernel sources.
echo "Downloading kernel..."
curl "$KERNEL_URL" > "$KERNEL_ARCHIVE"
echo "Extracting kernel sources..."
tar xf "$KERNEL_ARCHIVE"
cd "$KERNEL"

# Copy base kernel config from Firecracker resources.
cp "$FC_DIR/resources/microvm-kernel-x86_64.config" .config

# Prepare initramfs.
echo "Preparing initramfs..."
mkdir -p initramfs
cp "../$INIT_PROJ/target/x86_64-unknown-linux-musl/release/dirtying_init" initramfs/init
pushd initramfs &>/dev/null
fakeroot mkdir -p dev
fakeroot mknod dev/console c 5 1
fakeroot chown root init
find . | cpio -H newc -o > ../initramfs.cpio
fakeroot chown root ../initramfs.cpio
popd &>/dev/null

# Update kernel config with initramfs settings.
echo "Writing initramfs settings in kernel config..."
sed -i 's/CONFIG_INITRAMFS_SOURCE=""/CONFIG_INITRAMFS_SOURCE="initramfs.cpio"/' .config
echo "CONFIG_INITRAMFS_ROOT_GID=0" >> .config
echo "CONFIG_INITRAMFS_ROOT_UID=0" >> .config

# Build kernel.
echo "Building kernel..."
make vmlinux
cp vmlinux "$TEST_RESOURCE_DIR/test_noisy_elf.bin"

echo "Done!"

exit 0
