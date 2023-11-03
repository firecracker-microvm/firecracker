# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for vhost-user-blk backend."""

import os
import subprocess
import time
from subprocess import check_output

from framework import utils

MB = 1024 * 1024


def partuuid_and_disk_path(rootfs_ubuntu_22, disk_path):
    """
    We create a new file with specified path, get its partuuid and use it as a rootfs.
    """
    initial_size = rootfs_ubuntu_22.stat().st_size + 50 * MB
    disk_path.touch()
    os.truncate(disk_path, initial_size)
    check_output(f"echo type=83 | sfdisk {str(disk_path)}", shell=True)
    stdout = check_output(
        f"losetup --find --partscan --show {str(disk_path)}", shell=True
    )
    loop_dev = stdout.decode("ascii").strip()
    check_output(f"dd if={str(rootfs_ubuntu_22)} of={loop_dev}p1", shell=True)

    # UUID=$(sudo blkid -s UUID -o value "${loop_dev}p1")
    stdout = check_output(f"blkid -s PARTUUID -o value {loop_dev}p1", shell=True)
    partuuid = stdout.decode("ascii").strip()

    # cleanup: release loop device
    check_output(f"losetup -d {loop_dev}", shell=True)

    return (partuuid, disk_path)


VHOST_USER_SOCKET = "/vub.socket"


def spawn_vhost_user_backend(vm, host_mem_path, socket_path, readonly=False):
    """Spawn vhost-user-blk backend."""

    uid = vm.jailer.uid
    gid = vm.jailer.gid

    sp = f"{vm.chroot()}{socket_path}"
    args = ["vhost-user-blk", "-s", sp, "-b", host_mem_path]
    if readonly:
        args.append("-r")
    proc = subprocess.Popen(args)

    # Give the backend time to initialise.
    time.sleep(1)

    assert proc is not None and proc.poll() is None, "backend is not up"

    with utils.chroot(vm.chroot()):
        # The backend will create the socket path with root rights.
        # Change rights to the jailer's.
        os.chown(socket_path, uid, gid)

    return proc
