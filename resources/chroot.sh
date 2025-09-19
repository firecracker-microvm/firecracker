#!/usr/bin/env bash
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

# be verbose
set -x
PS4='+\t '

cp -ruv $rootfs/* /

packages_ubuntu="udev systemd-sysv openssh-server iproute2 curl socat python3-minimal iperf3 iputils-ping fio kmod tmux hwloc-nox vim-tiny trace-cmd linuxptp strace python3-boto3 pciutils"
packages_fedora="systemd openssh-server iproute curl socat python3 iperf3 iputils fio kmod tmux hwloc vim-enhanced trace-cmd linuxptp strace python3-boto3 pciutils"
packages_centos="systemd openssh-server iproute curl socat python3 iperf3 iputils fio kmod tmux hwloc vim-enhanced trace-cmd linuxptp strace passwd python3-boto3 pciutils" # not checked for python3-boto3
packages_arch="systemd git openssh iproute2 curl socat python3 iperf3 iputils fio kmod tmux hwloc vim trace-cmd strace python3-boto3 pciutils"

# Detect target OS
source /etc/os-release
TARGET_OS=$ID
TARGET_VERSION=$VERSION_ID

# msr-tools is only supported on x86-64.
arch=$(uname -m)
if [ "${arch}" == "x86_64" ]; then
    packages="$packages msr-tools cpuid"
fi

# Install packages based on target distro
case $TARGET_OS in
    "debian"|"ubuntu")

        export DEBIAN_FRONTEND=noninteractive
        apt update
        apt install -y --no-install-recommends $packages_ubuntu
        apt autoremove -y
        ;;

    "fedora")
        # RHEL-family package setup
        if [ "$TARGET_OS" = "fedora" ]; then
            dnf install -y $packages_fedora
            dnf clean all
        else
            yum install -y $packages_fedora
            yum clean all
        fi
        ;;

    "centos")
        # CentOS reached its end-of-life (EOL) on December 31, 2021. And is no longer supported. Changing the mirrors to vault.centos.org where they will be archived permanently.
        
        # Replace CentOS 8 repositories with Vault repositories
        sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*        
        sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
        yum update -y

        # CentOS package setup
        yum install -y $packages_centos
        yum clean all

        # # Enable SELinux, Security-Enhanced Linux (SELinux) is a security module integrated into the Linux kernel that enforces mandatory access control (MAC) policies. Developed by the NSA and Red Hat.
        # yum install -y selinux-policy-targeted
        # /usr/sbin/selinuxenabled && /usr/sbin/setenforce 1
        # sestatus
        ;;

    "arch")
        # Arch Linux specific setup
        packages_yay="linuxptp"
        
        # Update package databases
        pacman -Sy --noconfirm
        
        # Install base packages (needed for chroot environments)
        pacman -S --noconfirm base
        
        # Install required packages
        pacman -S --noconfirm $packages_arch

        # ///////////////////////////////////////
        # Install yay (AUR helper) and required AUR packages
        # Temp user configuration
        TEMP_USER="builduser"
        TEMP_BUILD_DIR="/tmp/builduser-build"
        TEMP_HOME="/tmp/builduser-home"

        # Step 1: Install essential tools (base-devel), required for AUR builds
        pacman -Sy --noconfirm base-devel

        # Step 2: Create a temporary user with a custom home directory
        useradd -d $TEMP_HOME -G wheel -s /bin/bash $TEMP_USER

        # Create the temporary build and home directories
        mkdir -p $TEMP_BUILD_DIR && chown $TEMP_USER:$TEMP_USER $TEMP_BUILD_DIR
        mkdir -p $TEMP_HOME && chown $TEMP_USER:$TEMP_USER $TEMP_HOME

        # Step 3: Grant temporary sudo access
        echo "$TEMP_USER ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

        # Step 4: Switch to the new user and install yay (multiline approach)
su - $TEMP_USER << EOF
export HOME=$TEMP_HOME
cd $TEMP_BUILD_DIR
git clone https://aur.archlinux.org/yay.git
cd yay
makepkg -si --noconfirm
EOF

        # Step 5: Install the specified packages using yay (multiline approach)
su - $TEMP_USER << EOF
export HOME=$TEMP_HOME
yay -S --noconfirm $packages_yay
EOF

        # Step 6: Clean up
        userdel $TEMP_USER
        rm -rf $TEMP_BUILD_DIR $TEMP_HOME
        sed -i "/$TEMP_USER ALL=(ALL) NOPASSWD: ALL/d" /etc/sudoers

        echo "Installation of yay packages is complete!"
        # ///////////////////////////////////////
        
        # Arch-specific configurations
        # Enable required services
        systemctl enable sshd.service
        
        # Set up basic locale
        echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
        locale-gen
        echo "LANG=en_US.UTF-8" > /etc/locale.conf
        
        # Set timezone
        ln -sf /usr/share/zoneinfo/UTC /etc/localtime
        ;;

    *)
        echo "Unsupported target OS: $TARGET_OS"
        exit 1
        ;;
esac

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
mkdir -p "/etc/systemd/system/sysinit.target.wants/"
ln -sf /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service

# Disable resolved and ntpd
#
rm -f /etc/systemd/system/multi-user.target.wants/systemd-resolved.service
rm -f /etc/systemd/system/dbus-org.freedesktop.resolve1.service
rm -f /etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service

# make /tmp a tmpfs
ln -s /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount
systemctl enable tmp.mount || true

# don't need this
systemctl disable e2scrub_reap.service || true
rm -vf /etc/systemd/system/timers.target.wants/*
# systemctl list-units --failed
# /lib/systemd/system/systemd-random-seed.service

systemctl enable var-lib-systemd.mount || true

# disable Predictable Network Interface Names to keep ethN names
# even with PCI enabled
ln -s /dev/null /etc/systemd/network/99-default.link

#### trim image https://wiki.ubuntu.com/ReducingDiskFootprint
# this does not save much, but oh well
rm -rf /usr/share/{doc,man,info,locale}

cat >> /etc/sysctl.conf <<EOF
# This avoids a SPECTRE vuln
kernel.unprivileged_bpf_disabled=1
EOF

# Build a manifest
case $TARGET_OS in
    "debian"|"ubuntu")
        dpkg-query -W --showformat='${Package} ${Version}\n' > /root/manifest
        ;;
    "fedora"|"centos")
        rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' > /root/manifest
        ;;
    "arch")
        pacman -Q | awk '{print $1 " " $2}' > /root/manifest
        ;;
esac
