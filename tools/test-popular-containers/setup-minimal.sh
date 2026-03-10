#!/bin/sh
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Minimal rootfs setup: just enough to boot with SSH and networking.
# Runs inside a Docker container via build_rootfs().

set -eux

. /etc/os-release
# On Ubuntu, installing openssh-server automatically sets up required SSH keys for the server.
# AL2023 and Alpine do not do this, so we should setup keys manually via `ssh-keygen`.
# Alpine additionally requires /var/empty to be present for sshd to start properly.
case $ID in
ubuntu)
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y openssh-server iproute2 udev
  apt clean
  ;;
amzn)
  dnf install -y openssh-server iproute systemd-udev passwd tar
  ssh-keygen -A
  dnf clean all
  ;;
alpine)
  apk add openssh openrc tar
  mkdir -p /var/empty
  ssh-keygen -A
  rc-update add sshd
  rc-update add local default
  echo "ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100" >>/etc/inittab
  apk cache clean
  ;;
esac

passwd -d root

if [ ! -f /work/id_rsa.pub ]; then
  echo "Host SSH public key not found"
  exit 1
fi

# Install host SSH public key
install -d -m 0700 /root/.ssh
cp /work/id_rsa.pub /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys

if [ -d /usr/lib/systemd ]; then
  # Enable fcnet for systemd-based images
  mkdir -pv /etc/systemd/system/sysinit.target.wants
  ln -svf /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service

  # The serial getty service hooks up the login prompt to the kernel console
  # at ttyS0 (where Firecracker connects its serial console). We'll set it up
  # for autologin to avoid the login prompt.
  mkdir "/etc/systemd/system/serial-getty@ttyS0.service.d/"
  cat <<'EOF' >"/etc/systemd/system/serial-getty@ttyS0.service.d/override.conf"
    [Service]
    # systemd requires this empty ExecStart line to override
    ExecStart=
    ExecStart=-/sbin/agetty --autologin root -o '-p -- \\u' --keep-baud 115200,38400,9600 %I dumb
EOF
else
  # Enable fcnet for OpenRC-based images
  cp -v fcnet.start /etc/local.d
fi

# Copy /var back to bind-mounted rootfs.
# Required for things like systemd and apt to work
# ($rootfs variable set via docker --env $rootfs <host_rootfs_dir>)
cp -r /var $rootfs
