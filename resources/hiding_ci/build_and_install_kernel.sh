#!/bin/bash
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

check_root() {
  # We need sudo privileges to install the kernel
  if [ "$(id -u)" -ne 0 ]; then
    echo "To install, this script must be run as root or with sudo privileges"
    exit 1
  fi
}

check_userspace() {
  # Currently this script only works on Ubuntu and AL2023
  if grep -qi 'ubuntu' /etc/os-release; then
    USERSPACE="UBUNTU"
    return 0
  fi

  if grep -qi 'al2023' /etc/os-release; then
    USERSPACE="AL2023"
    return 0
  fi

  echo "This script currently only works on Ubuntu and Amazon Linux 2023."
  exit 1
}

tidy_up() {
  # Some cleanup after we are done
  echo "Cleaning up.."
  cd $START_DIR
  rm -rf $TMP_BUILD_DIR
}

confirm() {
  if [[ "$*" == *"--no-install"* ]]; then
    echo "Not installing new kernel."

    if [[ "$*" == *"--tidy"* ]]; then
      tidy_up
    fi

    exit 0
  fi

  if [[ "$*" == *"--install"* ]]; then
    return 0
  fi

  while true; do
    read -p "Do you want to install the new kernel? (y/n) " yn
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

apply_patch_file() {
  git apply $1
}

apply_patch_or_series() {
  case "$1" in
  *.patch) apply_patch_file $1 ;;
  *) echo "Skipping non-patch file" $1 ;;
  esac
}

check_new_config() {
  if [[ -e "/boot/config-$KERNEL_VERSION" ]]; then
    return 0;
  fi

  echo "Storing new config in /boot/config-$KERNEL_VERSION"
  cp .config /boot/config-$KERNEL_VERSION
}

check_override_presence() {
  while IFS= read -r line; do
    if ! grep -Fq "$line" .config; then
      echo "Missing config: $line"
      exit 1
    fi
  done <"$KERNEL_CONFIG_OVERRIDES"

  echo "All overrides correctly applied.."
}

ubuntu_update_boot() {
  echo "Update initramfs"
  update-initramfs -c -k $KERNEL_VERSION
  echo "Updating GRUB..."
  update-grub
}

al2023_update_boot() {
  echo "Installing ENA driver for AL2023"
  $START_DIR/install_ena.sh $KERNEL_VERSION $START_DIR/dkms.conf

  # Just ensure we are back in the build dir
  cd $TMP_BUILD_DIR

  echo "Creating the new ram disk"
  dracut --kver $KERNEL_VERSION -f -v

  # This varies from x86 and ARM so capture what was generated
  # We add the || true here due to the fact that we have pipefail enabled
  # this causes a non 0 exit when ls cant find vmlinux or vmlinux
  VM_LINUX_LOCATION=$(ls /boot/vmlinu{x,z}-$KERNEL_VERSION 2>/dev/null | head -n1 || true)

  echo "Updating GRUB..."
  grubby --grub2 --add-kernel $VM_LINUX_LOCATION \
    --title="Secret Hiding" \
    --initrd=/boot/initramfs-$KERNEL_VERSION.img --copy-default
  grubby --set-default $VM_LINUX_LOCATION
}

update_boot_config() {
  case "$USERSPACE" in
  UBUNTU) ubuntu_update_boot ;;
  AL2023) al2023_update_boot ;;
  *)
    echo "Unknown userspace"
    exit 1
    ;;
  esac
}

KERNEL_URL=$(cat kernel_url)
KERNEL_COMMIT_HASH=$(cat kernel_commit_hash)
KERNEL_PATCHES_DIR=$(pwd)/linux_patches
KERNEL_CONFIG_OVERRIDES=$(pwd)/kernel_config_overrides

TMP_BUILD_DIR=$(mktemp -d -t kernel-build-XXXX)

START_DIR=$(pwd)

cd $TMP_BUILD_DIR

echo "Cloning kernel repository into" $TMP_BUILD_DIR

# We checkout the repository that way to make it as
# small and fast as possible
git init
git remote add origin $KERNEL_URL
git fetch --depth 1 origin $KERNEL_COMMIT_HASH
git checkout FETCH_HEAD

# Apply our patches on top
for PATCH in $KERNEL_PATCHES_DIR/*.*; do
  echo "Applying patch:" $(basename $PATCH)
  apply_patch_or_series $PATCH
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
scripts/kconfig/merge_config.sh -m .config $KERNEL_CONFIG_OVERRIDES

check_override_presence

# We run this again to default options now changed by
# the disabling of the ubuntu keys
make olddefconfig

echo "Building kernel this may take a while"
make -s -j $(nproc)
echo "Building kernel modules"
make modules -s -j $(nproc)
echo "Kernel build complete!"

KERNEL_VERSION=$(KERNELVERSION=$(make -s kernelversion) ./scripts/setlocalversion)

echo "New kernel version:" $KERNEL_VERSION

# Make sure a user really wants to install this kernel
confirm "$@"

check_root
check_userspace

echo "Installing kernel modules..."
make INSTALL_MOD_STRIP=1 modules_install
echo "Installing kernel..."
make INSTALL_MOD_STRIP=1 install

update_boot_config

check_new_config

echo "Kernel built and installed successfully!"

tidy_up
