# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for vhost-user-block device."""

import os
import subprocess
import time

from framework import utils

VHOST_USER_SOCKET = "/vub.socket"


def spawn_vhost_user_backend(vm, host_mem_path):
    """Spawn vhost-user-block backend."""

    uid = vm.jailer.uid
    gid = vm.jailer.gid

    sp = f"{vm.chroot()}{VHOST_USER_SOCKET}"
    args = ["vhost-user-blk", "-s", sp, "-b", host_mem_path, "-r"]
    proc = subprocess.Popen(args)

    time.sleep(1)
    if proc is None or proc.poll() is not None:
        print("vub is not running")

    with utils.chroot(vm.chroot()):
        # The backend will create the socket path with root rights.
        # Change rights to the jailer's.
        os.chown(VHOST_USER_SOCKET, uid, gid)
    return proc


def test_vhost_user_block(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    This test simply tries to boot a VM with
    vhost-user-block as a root device.
    """

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key

    vm.spawn()

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    _backend = spawn_vhost_user_backend(vm, rootfs_path)

    vm.basic_config()
    vm.add_vhost_user_block("1", VHOST_USER_SOCKET, is_root_device=True)
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0
