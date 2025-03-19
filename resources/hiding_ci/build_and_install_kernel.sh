#!/bin/bash
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# We need sudo privilleges to install the kernel
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root or with sudo privileges"
  exit 1
fi

# Currently this script only works on Ubuntu instances
if ! grep -qi 'ubuntu' /etc/os-release; then
  echo "This script currently only works on Ubuntu."
  exit 1
fi

confirm() {
  if [[ "$*" == *"-y"* ]]; then
    return 0
  fi

  while true; do
    echo "This script will build and install a new kernel. Run this script at your own risk"
    read -p "Do you want to continue? (y/n) " yn
    case $yn in
    [Yy]*) return 0 ;;
    [Nn]*)
      echo "Exiting..."
      exit 1
      ;;
    *) echo "Please answer yes or no." ;;
    esac
  done
}

# Make sure a user really wants to run this script
confirm "$@"

KERNEL_URL=$(cat kernel_url)
KERNEL_COMMIT_HASH=$(cat kernel_commit_hash)
KERNEL_VERSION=$(cat kernel_version)
KERNEL_PATCHES_DIR=$(pwd)/patches
KERNEL_CONFIG_OVERRIDES=$(pwd)/kernel_config_overrides

TMP_BUILD_DIR=$(mktemp -d -t kernel-build-XXXX)

pushd .
cd $TMP_BUILD_DIR

echo "Cloning kernel repository into" $TMP_BUILD_DIR

# We checkout the repository that way to make it as
# small and fast as possible
git init
git remote add origin $KERNEL_URL
git fetch --depth 1 origin $KERNEL_COMMIT_HASH
git checkout FETCH_HEAD

# Apply our patches on top
for PATCH in $KERNEL_PATCHES_DIR/*.patch; do
  echo "Applying patch:" $(basename $PATCH)
  git apply $PATCH
done

echo "Making kernel config ready for build"
# We use olddefconfig to automatically pull in the
# config from the AMI and update to the newest
# defaults
make olddefconfig

# Disable the ubuntu keys
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS

# Apply our config overrides on top of the config
scripts/kconfig/merge_config.sh .config $KERNEL_CONFIG_OVERRIDES

# Finally run olddefconfig again to make sure any
# new options are configured before build
make olddefconfig

echo "Building kernel this may take a while"
make -j $(nproc)
echo "Building kernel modules"
make modules -j $(nproc)
echo "Kernel build complete!"

echo "Installing kernel modules..."
make INSTALL_MOD_STRIP=1 modules_install
echo "Installing kernel..."
make INSTALL_MOD_STRIP=1 install
echo "Update initramfs"
update-initramfs -c -k $KERNEL_VERSION
echo "Updating GRUB..."
update-grub

echo "Kernel built and installed successfully!"

# Some cleanup after we are done
popd
rm -rf $TMP_BUILD_DIR
