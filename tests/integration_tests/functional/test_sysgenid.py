# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test SysGenID device"""

import pytest

SYSGENID_BIN_PATH = "/tmp/sysgenid"
SYSGENID_OUT_PATH = "/tmp/sysgenid.out"


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
    vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -r >{SYSGENID_OUT_PATH} 2>&1 &")

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        _, stdout, _ = vm.ssh.check_output(f"tail -n1 {SYSGENID_OUT_PATH}")
        assert stdout.strip() == f"SysGenID: {i + 1}"


def test_sysgenid_via_poll_and_nonblocking_read(uvm_booted):
    """Read the SysGenID value via poll() and non-blocking read()"""
    vm = uvm_booted

    # Start poll() / non-blocking read() loop.
    vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -p >{SYSGENID_OUT_PATH} 2>&1 &")

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        _, stdout, _ = vm.ssh.check_output(f"tail -n1 {SYSGENID_OUT_PATH}")
        assert stdout.strip() == f"SysGenID: {i + 1}"


def test_sysgenid_via_mmap(uvm_booted):
    """Read the SysGenID value via mmap()"""
    vm = uvm_booted

    vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -m >{SYSGENID_OUT_PATH} 2>&1 &")

    for i in range(5):
        vm.ssh.check_output(f"{SYSGENID_BIN_PATH} -b")
        _, stdout, _ = vm.ssh.check_output(f"tail -n1 {SYSGENID_OUT_PATH}")
        assert stdout.strip() == f"SysGenID: {i + 1}"
