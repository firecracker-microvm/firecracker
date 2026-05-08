#!/bin/bash
# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

# be verbose
set -x
PS4='+\t '

packages="systemd-udev openssh-server iproute socat iperf3 iputils fio fio-engine-libaio kmod tmux hwloc vim-minimal trace-cmd strace python3-boto3 pciutils tar passwd procps-ng findutils e2fsprogs"

# certain packages that are required in our CI tests are not available on Amazon Linux.
# Build these from source so tests work properly.
function build_unavailable_packages() {
  dnf install -y gcc make git

  # linuxptp (pinned to v4.4)
  git clone --branch v4.4 --depth 1 https://git.code.sf.net/p/linuxptp/code /tmp/linuxptp
  make -C /tmp/linuxptp
  make -C /tmp/linuxptp install prefix=/usr
  rm -rf /tmp/linuxptp

  # msr-tools (x86_64 only)
  if [ "$(uname -m)" == "x86_64" ]; then
    git clone https://github.com/intel/msr-tools.git /tmp/msr-tools
    cd /tmp/msr-tools
    CFLAGS="-Wall -O2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64"
    gcc $CFLAGS -o /usr/sbin/rdmsr rdmsr.c
    gcc $CFLAGS -o /usr/sbin/wrmsr wrmsr.c
    cd /
    rm -rf /tmp/msr-tools
  fi

  dnf remove -y gcc make git
}

arch=$(uname -m)
if [ "${arch}" == "x86_64" ]; then
  packages="$packages cpuid"
fi

# Update local package list and install packages
dnf makecache
dnf install --setopt=install_weak_deps=False -y $packages
build_unavailable_packages

# Set a hostname.
echo "al2023-fc-uvm" >/etc/hostname

passwd -d root

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

# Generate an SSH key for openssh-server to use.
ssh-keygen -A

# Setup fcnet service. This is a custom Firecracker setup for assigning IPs
# to the network interfaces in the guests spawned by the CI.
# openssh-server on AL2023 requires an SSH key to be generated (vs. ubuntu which does not need this).
ln -s /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service

# Disable resolved and ntpd
rm -f /etc/systemd/system/multi-user.target.wants/systemd-resolved.service
rm -f /etc/systemd/system/dbus-org.freedesktop.resolve1.service
rm -f /etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service

# don't need this
rm -vf /etc/systemd/system/timers.target.wants/*

systemctl enable var-lib-systemd.mount

# disable Predictable Network Interface Names to keep ethN names
# even with PCI enabled
ln -s /dev/null /etc/systemd/network/99-default.link

#### trim image https://wiki.ubuntu.com/ReducingDiskFootprint
# this does not save much, but oh well
rm -rf /usr/share/{doc,man,info,locale}

cat >>/etc/sysctl.conf <<EOF
# This avoids a SPECTRE vuln
kernel.unprivileged_bpf_disabled=1
EOF

# Drop dnf caches to reduce size
dnf clean all

# Build a manifest
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' >/root/manifest

# Make systemd mountpoint
mkdir -pv $rootfs/var/lib/systemd

# So rpm works
mkdir -pv $rootfs/var/lib/rpm
