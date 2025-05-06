#!/bin/bash
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail
set -x

cd $(dirname $0)
TOPDIR=$(git rev-parse --show-cdup)

function make_rootfs {
    local LABEL=$1
    local rootfs=$LABEL
    local IMG=$LABEL.ext4
    mkdir $LABEL
    ctr image pull docker.io/library/$LABEL
    ctr image mount --rw docker.io/library/$LABEL $LABEL
    MNT_SIZE=$(du -sb $LABEL |cut -f1)
    SIZE=$(( $MNT_SIZE + 512 * 2**20 ))

    # Generate key for ssh access from host
    if [ ! -s id_rsa ]; then
        ssh-keygen -f id_rsa -N ""
    fi
    cp id_rsa $rootfs.id_rsa

    truncate -s "$SIZE" "$IMG"
    mkfs.ext4 -F "$IMG" -d $LABEL
    ctr image unmount $LABEL
    rmdir $LABEL

    mkdir mnt
    mount $IMG mnt
    install -d -m 0600 "mnt/root/.ssh/"
    cp -v id_rsa.pub "mnt/root/.ssh/authorized_keys"
    cp -rvf $TOPDIR/resources/overlay/* mnt
    SYSINIT=mnt/etc/systemd/system/sysinit.target.wants
    mkdir -pv $SYSINIT
    ln -svf /etc/systemd/system/fcnet.service $SYSINIT/fcnet.service
    mkdir mnt/etc/local.d
    cp -v fcnet.start mnt/etc/local.d
    umount -l mnt
    rmdir mnt

    # --timezone=off parameter is needed to prevent systemd-nspawn from
    # bind-mounting /etc/timezone, which causes a file conflict in Ubuntu 24.04
    systemd-nspawn --timezone=off --pipe -i $IMG /bin/sh <<EOF
set -x
. /etc/os-release
case \$ID in
ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y openssh-server iproute2
    ;;
alpine)
    apk add openssh openrc
    rc-update add sshd
    rc-update add local default
    echo "ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100" >>/etc/inittab
    ;;
amzn)
    dnf update
    dnf install -y openssh-server iproute passwd
    # re-do this
    ln -svf /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service
    rm -fv /etc/systemd/system/getty.target.wants/getty@tty1.service
    ;;
esac
passwd -d root
EOF
}

make_rootfs alpine:latest
make_rootfs ubuntu:22.04
make_rootfs ubuntu:24.04
make_rootfs ubuntu:24.10
# make_rootfs ubuntu:latest
make_rootfs amazonlinux:2023
