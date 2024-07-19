# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenario exercising api server functionality."""

import socket

from framework.utils import check_output


def test_api_socket_in_use(uvm_plain):
    """
    Test error message when api socket is already in use.

    This is a very frequent scenario when Firecracker cannot
    start due to the socket being left open from previous runs.
    Check that the error message is a fixed one and that it also
    contains the name of the path.
    """
    microvm = uvm_plain

    cmd = "mkdir {}/run".format(microvm.chroot())
    check_output(cmd)

    sock = socket.socket(socket.AF_UNIX)
    sock.bind(microvm.jailer.api_socket_path())
    microvm.spawn()
    msg = "Failed to open the API socket at: /run/firecracker.socket. Check that it is not already used."
    microvm.check_log_message(msg)

    microvm.mark_killed()
