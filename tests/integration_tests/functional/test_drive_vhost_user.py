# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for vhost-user-block device."""

from framework import utils
from framework.utils_vhost_user_backend import (
    VHOST_USER_SOCKET,
    spawn_vhost_user_backend,
)


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
    _backend = spawn_vhost_user_backend(vm, rootfs_path, readonly=True)

    vm.basic_config()
    vm.add_vhost_user_block("1", VHOST_USER_SOCKET, is_root_device=True)
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0
