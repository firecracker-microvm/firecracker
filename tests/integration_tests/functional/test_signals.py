# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests scenarios for Firecracker signal handling."""

import os
from signal import SIGBUS, SIGSEGV
from time import sleep

import pytest

import host_tools.logging as log_tools


@pytest.mark.parametrize(
    "signum",
    [SIGBUS, SIGSEGV]
)
def test_sigbus_sigsegv(test_microvm_with_api, signum):
    """Test signal handling for `SIGBUS` and `SIGSEGV`."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # We don't need to monitor the memory for this test.
    test_microvm.memory_events_queue = None

    test_microvm.basic_config()

    # Configure logging.
    log_fifo_path = os.path.join(test_microvm.path, 'log_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)

    response = test_microvm.logger.put(
        log_fifo=test_microvm.create_jailed_resource(log_fifo.path),
        level='Error',
        show_level=False,
        show_log_origin=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    test_microvm.start()
    firecracker_pid = int(test_microvm.jailer_clone_pid)

    sleep(0.5)
    os.kill(firecracker_pid, signum)

    msg = 'Shutting down VM after intercepting signal {}'.format(signum)
    lines = log_fifo.sequential_reader(5)
    msg_found = False
    for line in lines:
        if msg in line:
            msg_found = True
            break
    assert msg_found
