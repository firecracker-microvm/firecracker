# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for vhost-user-block device."""

from framework import utils
from framework.utils_drive import spawn_vhost_user_backend


def test_vhost_user_block(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    This test simply tries to boot a VM with
    vhost-user-block as a root device.
    """

    vhost_user_socket = "/vub.socket"

    vm = microvm_factory.build(guest_kernel, None, monitor_memory=False)

    # Converting path from tmpfs ("./srv/..") to local
    # path on the host ("../build/..")
    rootfs_path = utils.to_local_dir_path(str(rootfs_ubuntu_22))
    # Launching vhost-user-block backend
    _backend = spawn_vhost_user_backend(vm, rootfs_path, vhost_user_socket, True)

    # We need to setup ssh keys manually because we did not specify rootfs
    # in microvm_factory.build method
    ssh_key = rootfs_ubuntu_22.with_suffix(".id_rsa")
    vm.ssh_key = ssh_key
    vm.spawn()
    vm.basic_config(add_root_device=False)
    vm.add_vhost_user_drive("rootfs", vhost_user_socket, is_root_device=True)
    vm.add_net_iface()
    vm.start()

    # Attempt to connect to the VM.
    # Verify if guest can run commands.
    exit_code, _, _ = vm.ssh.run("ls")
    assert exit_code == 0
