# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test SysGenID device"""

import pytest

SYSGENID_BIN_PATH = "/tmp/sysgenid"
SYSGENID_OUT_PATH = "/tmp/sysgenid.out"


@pytest.fixture(scope="function")
def vm_with_sysgenid(uvm_plain_any, bin_sysgenid_path):
    """Create a VM with SysGenID support and the `sysgenid` test binary under `/tmp/sysgenid`"""
    basevm = uvm_plain_any
    basevm.spawn()

    basevm.basic_config()
    basevm.add_net_iface()
    basevm.start()
    basevm.ssh.scp_put(bin_sysgenid_path, SYSGENID_BIN_PATH)

    yield basevm


def test_sysgenid_via_blocking_read(vm_with_sysgenid):
    """Read the SysGenID value via blocking read()"""
    vm = vm_with_sysgenid

    # Start blocking read()/write() loop.
    vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -r >{SYSGENID_OUT_PATH} 2>&1 &")

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        _, stdout, _ = vm.ssh.check_output(f"tail -n1 {SYSGENID_OUT_PATH}")
        assert stdout.strip() == f"SysGenID: {i + 1}"


def test_sysgenid_via_poll_and_nonblocking_read(vm_with_sysgenid):
    """Read the SysGenID value via poll() and non-blocking read()"""
    vm = vm_with_sysgenid

    # Start poll() / non-blocking read() loop.
    vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -p >{SYSGENID_OUT_PATH} 2>&1 &")

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        _, stdout, _ = vm.ssh.check_output(f"tail -n1 {SYSGENID_OUT_PATH}")
        assert stdout.strip() == f"SysGenID: {i + 1}"


def test_sysgenid_via_mmap(vm_with_sysgenid):
    """Read the SysGenID value via mmap()"""
    vm = vm_with_sysgenid

    vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -m >{SYSGENID_OUT_PATH} 2>&1 &")

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        _, stdout, _ = vm.ssh.check_output(f"tail -n1 {SYSGENID_OUT_PATH}")
        assert stdout.strip() == f"SysGenID: {i + 1}"
