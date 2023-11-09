# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for vhost-user-blk backend."""

import os
import subprocess
import time

from framework import utils

VHOST_USER_SOCKET = "/vub.socket"


def spawn_vhost_user_backend(vm, host_mem_path, readonly=False):
    """Spawn vhost-user-blk backend."""

    uid = vm.jailer.uid
    gid = vm.jailer.gid

    socket_path = f"{vm.chroot()}{VHOST_USER_SOCKET}"
    args = ["vhost-user-blk", "-s", socket_path, "-b", host_mem_path]
    if readonly:
        args.append("-r")
    proc = subprocess.Popen(args)

    # Give the backend time to initialise.
    time.sleep(1)

    assert proc is not None and proc.poll() is None, "backend is not up"

    with utils.chroot(vm.chroot()):
        # The backend will create the socket path with root rights.
        # Change rights to the jailer's.
        os.chown(VHOST_USER_SOCKET, uid, gid)

    return proc
