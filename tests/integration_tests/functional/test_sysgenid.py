# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test SysGenID device"""

import pytest
from tenacity import Retrying, stop_after_delay, wait_fixed

from framework.utils_wait import start_guest_process

SYSGENID_BIN_PATH = "/tmp/sysgenid"
# Printed by the helper once it has opened the device.
SYSGENID_READY = "Watching SysGenID"


def wait_for_sysgenid(vm, out_path, expected):
    """Wait for the watcher to report `expected`; it prints asynchronously."""
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(5), reraise=True
    ):
        with attempt:
            _, stdout, _ = vm.ssh.check_output(f"tail -n1 {out_path}")
            assert stdout.strip() == f"SysGenID: {expected}"


# Decorates the shared `uvm_booted` stage via same-name chaining: every booted
# VM in this module carries the sysgenid test binary at SYSGENID_BIN_PATH.
@pytest.fixture
def uvm_booted(uvm_booted, bin_sysgenid_path):
    """Booted microVM with the sysgenid test binary installed."""
    uvm_booted.ssh.scp_put(bin_sysgenid_path, SYSGENID_BIN_PATH)
    return uvm_booted


def test_sysgenid_via_blocking_read(uvm_booted):
    """Read the SysGenID value via blocking read()"""
    vm = uvm_booted

    # Start blocking read()/write() loop.
    out_path = start_guest_process(vm, f"{SYSGENID_BIN_PATH} -r", SYSGENID_READY)

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        wait_for_sysgenid(vm, out_path, i + 1)


def test_sysgenid_via_poll_and_nonblocking_read(uvm_booted):
    """Read the SysGenID value via poll() and non-blocking read()"""
    vm = uvm_booted

    # Start poll() / non-blocking read() loop.
    out_path = start_guest_process(vm, f"{SYSGENID_BIN_PATH} -p", SYSGENID_READY)

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        wait_for_sysgenid(vm, out_path, i + 1)


def test_sysgenid_via_mmap(uvm_booted):
    """Read the SysGenID value via mmap()"""
    vm = uvm_booted

    out_path = start_guest_process(vm, f"{SYSGENID_BIN_PATH} -m", SYSGENID_READY)

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        wait_for_sysgenid(vm, out_path, i + 1)
