#!/usr/bin/env bash

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Script that builds a kernel for CI.

set -euo pipefail

# Full path to the firecracker directory
FC_ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)

# Full path to the firecracker tools directory and include common functionalities
FC_TOOLS_DIR="$FC_ROOT_DIR/tools"
source "$FC_TOOLS_DIR/functions"

# Full path to the directory for kernel build
FC_KERNEL_DIR="$FC_ROOT_DIR/build/kernel"
mkdir -p "$FC_KERNEL_DIR"


# Extract kernel version (major & minor) from .config file
extract_kernel_version() {
    echo "Extracting kernel version..."

    case $(uname -m) in
        "x86_64")
            local arch="x86"
            ;;
        "aarch64")
            local arch="arm64"
            ;;
    esac
    KERNEL_VERSION=$(grep -o -E "^# Linux\/$arch [0-9]+\.[0-9]+" "$KERNEL_CONFIG" | cut -d ' ' -f 3)
    echo "Kernel version: $KERNEL_VERSION"
}

# Download the latest kernel source for the given kernel version
download_kernel_source() {
    echo "Downloading the latest patch version for v$KERNEL_VERSION..."
    pushd "$FC_KERNEL_DIR" >/dev/null

    local major_version="${KERNEL_VERSION%%.*}"
    local url_base="https://cdn.kernel.org/pub/linux/kernel"
    LATEST_VERSION=$( \
        curl -s $url_base/v$major_version.x/ \
        | grep -o "linux-$KERNEL_VERSION\.[0-9]*\.tar.xz" \
        | sort -rn -t . -k 3 \
        | head -n 1)
    local download_url="$url_base/v$major_version.x/$LATEST_VERSION"
    echo "URL: $download_url"

    curl -L $download_url > $LATEST_VERSION
    popd >/dev/null
}

# Extract the kernel source
extract_kernel_source() {
    echo "Extracting the kernel source..."
    pushd "$FC_KERNEL_DIR" >/dev/null

    KERNEL_DEST_DIR="$FC_KERNEL_DIR/linux-$KERNEL_VERSION"
    mkdir -p $KERNEL_DEST_DIR
    tar --skip-old-files --strip-components=1 -xf $LATEST_VERSION -C $KERNEL_DEST_DIR

    popd >/dev/null
}

# Build kernel from source
build_kernel() {
    echo "Building kernel from source..."
    cp "$KERNEL_CONFIG" "$KERNEL_DEST_DIR/.config"
    pushd "$KERNEL_DEST_DIR" >/dev/null

    local arch=$(uname -m)
    case $arch in
        "x86_64")
            local target="vmlinux"
            local binary_path="$target"
            ;;
        "aarch64")
            local target="Image"
            local binary_path="arch/arm64/boot/$target"
            ;;
    esac

    make olddefconfig
    make -j $NPROC $target
    local binary_name="vmlinux-$KERNEL_VERSION-$arch.bin"
    cp $binary_path $binary_name

    popd >/dev/null

    local full_binary_path="$KERNEL_DEST_DIR/$binary_name"
    echo "Kernel binary placed in ${full_binary_path##$FC_ROOT_DIR/}"
}


main() {
    KERNEL_CONFIG="$1"
    NPROC="$2"
    
    # Extract the kernel version from .config file.
    extract_kernel_version
    
    # Download the latest kernel source for the given kernel version.
    download_kernel_source
    
    # Extract the downloaded kernel source
    extract_kernel_source
    
    # Build kernel
    build_kernel
}

main "$1" "$2"
