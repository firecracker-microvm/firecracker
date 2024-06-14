#!/bin/bash
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

# be verbose
set -x
PS4='+\t '

cp -ruv $rootfs/* /

packages="udev systemd-sysv openssh-server iproute2 curl socat python3-minimal iperf3 iputils-ping fio kmod tmux hwloc-nox vim-tiny trace-cmd linuxptp strace"

# msr-tools is only supported on x86-64.
arch=$(uname -m)
if [ "${arch}" == "x86_64" ]; then
    packages="$packages msr-tools cpuid"
fi

export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y --no-install-recommends $packages
apt autoremove

# Set a hostname.
echo "ubuntu-fc-uvm" > /etc/hostname

passwd -d root

# The serial getty service hooks up the login prompt to the kernel console
# at ttyS0 (where Firecracker connects its serial console). We'll set it up
# for autologin to avoid the login prompt.
for console in ttyS0; do
    mkdir "/etc/systemd/system/serial-getty@$console.service.d/"
    cat <<'EOF' > "/etc/systemd/system/serial-getty@$console.service.d/override.conf"
[Service]
# systemd requires this empty ExecStart line to override
ExecStart=
ExecStart=-/sbin/agetty --autologin root -o '-p -- \\u' --keep-baud 115200,38400,9600 %I dumb
EOF
done

# Setup fcnet service. This is a custom Firecracker setup for assigning IPs
# to the network interfaces in the guests spawned by the CI.
ln -s /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service

# Disable resolved and ntpd
#
rm -f /etc/systemd/system/multi-user.target.wants/systemd-resolved.service
rm -f /etc/systemd/system/dbus-org.freedesktop.resolve1.service
rm -f /etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service

# make /tmp a tmpfs
ln -s /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount
systemctl enable tmp.mount

# don't need this
systemctl disable e2scrub_reap.service
rm -vf /etc/systemd/system/timers.target.wants/*
# systemctl list-units --failed
# /lib/systemd/system/systemd-random-seed.service

systemctl enable var-lib-systemd.mount

#### trim image https://wiki.ubuntu.com/ReducingDiskFootprint
# this does not save much, but oh well
rm -rf /usr/share/{doc,man,info,locale}

cat >> /etc/sysctl.conf <<EOF
# This avoids a SPECTRE vuln
kernel.unprivileged_bpf_disabled=1
EOF

# Build a manifest
dpkg-query --show >/root/manifest
