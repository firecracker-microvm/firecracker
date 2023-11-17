# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for vhost-user-blk backend."""

import os
import subprocess
import time
from enum import Enum
from pathlib import Path
from subprocess import check_output

from framework import utils

MB = 1024 * 1024


class VhostUserBlkBackendType(Enum):
    """vhost-user-blk backend type"""

    QEMU = "Qemu"
    CROSVM = "Crosvm"


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


CROSVM_CTR_SOCKET_NAME = "crosvm_ctr.socket"


def spawn_vhost_user_backend(
    vm,
    host_mem_path,
    socket_path,
    readonly=False,
    backend=VhostUserBlkBackendType.CROSVM,
):
    """Spawn vhost-user-blk backend."""

    uid = vm.jailer.uid
    gid = vm.jailer.gid
    host_vhost_user_socket_path = Path(vm.chroot()) / socket_path.strip("/")

    if backend == VhostUserBlkBackendType.QEMU:
        args = [
            "vhost-user-blk",
            "--socket-path",
            host_vhost_user_socket_path,
            "--blk-file",
            host_mem_path,
        ]
        if readonly:
            args.append("--read-only")
    elif backend == VhostUserBlkBackendType.CROSVM:
        crosvm_ctr_socket_path = Path(vm.chroot()) / CROSVM_CTR_SOCKET_NAME.strip("/")
        ro = ",ro" if readonly else ""
        args = [
            "crosvm",
            "--log-level",
            "off",
            "devices",
            "--disable-sandbox",
            "--control-socket",
            crosvm_ctr_socket_path,
            "--block",
            f"vhost={host_vhost_user_socket_path},path={host_mem_path}{ro}",
        ]
        if os.path.exists(crosvm_ctr_socket_path):
            os.remove(crosvm_ctr_socket_path)
    else:
        assert False, f"unknown vhost-user-blk backend `{backend}`"
    proc = subprocess.Popen(args)

    # Give the backend time to initialise.
    time.sleep(1)

    assert proc is not None and proc.poll() is None, "backend is not up"

    with utils.chroot(vm.chroot()):
        # The backend will create the socket path with root rights.
        # Change rights to the jailer's.
        os.chown(socket_path, uid, gid)

    return proc


def resize_vhost_user_drive(vm, new_size):
    """
    Resize vhost-user-blk drive and send config change notification.

    This only works with the crosvm vhost-user-blk backend.
    New size is in MB.
    """

    crosvm_ctr_socket_path = Path(vm.chroot()) / CROSVM_CTR_SOCKET_NAME.strip("/")
    assert os.path.exists(
        crosvm_ctr_socket_path
    ), "crosvm backend must be spawned first"

    utils.run_cmd(
        f"crosvm disk resize 0 {new_size * 1024 * 1024} {crosvm_ctr_socket_path}"
    )
