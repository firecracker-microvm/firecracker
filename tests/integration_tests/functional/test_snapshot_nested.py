# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for snapshots of microVMs running nested microVMs."""

import json
from pathlib import Path

import pytest
from tenacity import Retrying, stop_after_delay, wait_fixed

from framework.artifacts import pin_pci
from framework.defs import ARTIFACT_DIR

NESTED_DIR = "/tmp/nested"


def host_nested_virt_enabled():
    """Whether KVM on the host offers VMX/SVM to its guests."""
    for module in ("kvm_intel", "kvm_amd"):
        nested = Path(f"/sys/module/{module}/parameters/nested")
        if nested.exists():
            return nested.read_text(encoding="ascii").strip() in ("Y", "1")
    return False


pytestmark = [
    pytest.mark.skipif(
        not host_nested_virt_enabled(),
        reason="Host does not allow nested virtualization",
    ),
    # The transport plays no part in what is tested: vCPU state.
    pin_pci(True),
    pytest.mark.parametrize("mem_size_mib", [1024], indirect=True),
]


def run_in_nested(vm, command, expected):
    """Run `command` on the nested microVM's serial console and wait for `expected`."""
    vm.ssh.check_output(f"echo '{command}' > {NESTED_DIR}/console.in")
    wait_for_nested_console(vm, expected)


def wait_for_nested_console(vm, expected, timeout_s=30):
    """Wait for `expected` to show up on the nested microVM's serial console."""
    for attempt in Retrying(
        stop=stop_after_delay(timeout_s), wait=wait_fixed(0.5), reraise=True
    ):
        with attempt:
            _, stdout, _ = vm.ssh.check_output(f"cat {NESTED_DIR}/console.out")
            assert expected in stdout


# Shadows the conftest stage so that `uvm_restored` snapshots a microVM while
# it runs a nested microVM.
@pytest.fixture
def uvm_booted(uvm_booted, guest_kernel):
    """Booted microVM running a nested microVM."""
    vm = uvm_booted
    vm.ssh.check_output("test -c /dev/kvm")

    vm.ssh.check_output(f"mkdir -p {NESTED_DIR}")
    vm.ssh.scp_put(vm.fc_binary_path, f"{NESTED_DIR}/firecracker")
    vm.ssh.scp_put(guest_kernel.vmlinux, f"{NESTED_DIR}/vmlinux")
    vm.ssh.scp_put(ARTIFACT_DIR / "initramfs.cpio", f"{NESTED_DIR}/initramfs.cpio")
    config = {
        "boot-source": {
            "kernel_image_path": "vmlinux",
            "initrd_path": "initramfs.cpio",
            "boot_args": "console=ttyS0 reboot=k panic=1",
        },
        "drives": [],
        "machine-config": {"vcpu_count": 1, "mem_size_mib": 128},
    }
    vm.ssh.check_output(f"echo '{json.dumps(config)}' > {NESTED_DIR}/config.json")

    # The nested microVM's serial console reads from a FIFO that `sleep` keeps
    # open, so that commands can be written to it one at a time.
    vm.ssh.check_output(
        f"cd {NESTED_DIR} && mkfifo console.in"
        " && (setsid sleep infinity > console.in < /dev/null 2>&1 &)"
        " && (setsid ./firecracker --no-api --config-file config.json"
        " < console.in > console.out 2>&1 &)"
    )
    wait_for_nested_console(vm, "Welcome to fcinitrd")
    run_in_nested(vm, "echo booted-$((6*7))", "booted-42")
    return vm


def test_snapshot_nested_microvm(uvm_restored):
    """
    Check that a nested microVM keeps running across a snapshot and restore of
    the microVM running it.
    """
    vm = uvm_restored
    vm.ssh.check_output("pgrep -x firecracker")
    run_in_nested(vm, "echo restored-$((6*7))", "restored-42")
