#!/usr/bin/env bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Script that customizes a rootfs for CI images.
#

prepare_fc_rootfs() {
    BUILD_DIR="$1"
    SSH_DIR="$BUILD_DIR/ssh"
    RESOURCE_DIR="$2"

    packages="udev systemd-sysv openssh-server iproute2 acpid"
    apt-get update
    apt-get install -y --no-install-recommends $packages

    # ----------------------------------------------------
    # [BEGIN] ACPI related stuff
    # ----------------------------------------------------
    # Decribe the mapping between events and actions to be done by acpid (for the power button press event)
    cat <<EOF > "/etc/acpi/events/powerconf"
# ACPID config to power down machine if powerbutton is pressed, but only if
# no gnome-power-manager is running

event=button/power.*
action=/etc/acpi/actions/power.sh
EOF
    # Directory where we should add scripts that needs to be executed when ACPI events are detected
    mkdir "/etc/acpi/actions/"
    # Scripts to be executed when ACPI events are detected (we have just the one for shutdown)
    cat > /etc/acpi/actions/power.sh << EOF
#!/bin/sh

PATH=/sbin:/bin:/usr/bin

# Check session status using systemd
session_ids=$(systemd-loginctl list-sessions 2>/dev/null | awk '{print $1}')
for session in ${session_ids} ; do
        session_status=$(systemd-loginctl session-status ${session})
        echo "${session_status}" | grep -e '\(Active: yes\|State: active\)' &> /dev/null &&
                echo "${session_status}" | grep -e '\(gnome-settings-daemon\|kded4\|xfce4-power-manager\)' &> /dev/null && exit 0
done

# Get the ID of the first active X11 session: using ConsoleKit
uid_session=$(
ck-list-sessions 2>/dev/null | \
awk '
/^Session[0-9]+:$/ { uid = active = x11 = "" ; next }
{ gsub(/'\''/, "", $3) }
$1 == "unix-user" { uid = $3 }
$1 == "active" { active = $3 }
$1 == "x11-display" { x11 = $3 }
active == "TRUE" && x11 != "" {
        print uid
        exit
}')

# Check that there is a power manager, otherwise shut down.
[ "$uid_session" ] &&
ps axo uid,cmd | \
awk '
    $1 == '$uid_session' &&
        ($2 ~ /gnome-power-manager/ || $2 ~ /kpowersave/ ||
         $2 ~ /xfce4-power-manager/ || $2 ~ /\/usr\/libexec\/gnome-settings-daemon/ ||
         $2 ~ /kded4/ || $3 ~ /guidance-power-manager/) \
                { found = 1; exit }
    END { exit !found }
' ||
  shutdown -h now
EOF
    chmod +x /etc/acpi/actions/power.sh
    # ----------------------------------------------------
    # [END] ACPI related stuff
    # ----------------------------------------------------

    # Set a hostname.
    echo "ubuntu-fc-uvm" > "/etc/hostname"

    # The serial getty service hooks up the login prompt to the kernel console at
    # ttyS0 (where Firecracker connects its serial console).
    # We'll set it up for autologin to avoid the login prompt.
    mkdir "/etc/systemd/system/serial-getty@ttyS0.service.d/"
cat <<EOF > "/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root -o '-p -- \\u' --keep-baud 115200,38400,9600 %I $TERM
EOF

    # Setup fcnet service. This is a custom Firecracker
    # setup for assigning IPs to the network interfaces in the guests spawned
    # by the CI.
    cp "$RESOURCE_DIR/fcnet-setup.sh"  "/usr/local/bin/"
    chmod +x /usr/local/bin/fcnet-setup.sh
    touch /etc/systemd/system/fcnet.service
cat > /etc/systemd/system/fcnet.service << EOF
[Service]
Type=oneshot
ExecStart=/usr/local/bin/fcnet-setup.sh
[Install]
WantedBy=sshd.service
EOF
    ln -s /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service

    # Disable resolved and ntpd
    #
    rm -f /etc/systemd/system/multi-user.target.wants/systemd-resolved.service
    rm -f /etc/systemd/system/dbus-org.freedesktop.resolve1.service
    rm -f /etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service

    # Generate key for ssh access from host
    if [ ! -f "$SSH_DIR/id_rsa" ]; then
        mkdir -p "$SSH_DIR"
        ssh-keygen -f "$SSH_DIR/id_rsa" -N ""
    fi
    mkdir -m 0600 -p "/root/.ssh/"
    cp "$SSH_DIR/id_rsa.pub" "/root/.ssh/authorized_keys"

cat <<EOF > "/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root -o '-p -- \\u' --keep-baud 115200,38400,9600 %I $TERM
EOF
    passwd -d root
}

setup_specialized_rootfs() {
    BUILD_DIR="$1"
    RESOURCE_DIR="$2"

    packages="iperf3 curl fio iproute2"
    if [ "$(uname -m)" = "x86_64" ]; then
        packages="$packages cpuid"
    fi

    apt-get update
    apt-get install -y --no-install-recommends $packages

    # Copy init file sending the boot done signal.
    if [ -f "$BUILD_DIR/init" ]; then
        mv /sbin/init /sbin/openrc-init
        mv "$BUILD_DIR/init" /sbin/init
    fi

    # Copy fillmem tool used by balloon tests.
    mv "$BUILD_DIR/fillmem" /sbin/fillmem
    mv "$BUILD_DIR/readmem" /sbin/readmem

    # Copy script used to retrieve cache info.
    cp "$RESOURCE_DIR/get_cache_info.sh"  "/usr/local/bin/"
    chmod +x /usr/local/bin/get_cache_info.sh
}

create_partuuid_rootfs() {
    IMAGE="$1"
    PARTUUID_IMAGE="$2"

    initial_size=$(ls -l --block-size=M $IMAGE | cut -d ' ' -f 5)
    size=${initial_size//M/}

    fallocate -l "$((size + 50))M" "$PARTUUID_IMAGE"
    echo "type=83" | sfdisk "$PARTUUID_IMAGE"

    loop_dev=$(losetup --find --partscan --show "$PARTUUID_IMAGE")

    dd if="$IMAGE" of="${loop_dev}p1"
    losetup -d "$loop_dev"
}
