# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that firecracker works with GDB feature enabled."""

import os
import platform
import signal
import subprocess
import tempfile
from pathlib import Path

import pytest

import host_tools.cargo_build
from framework.microvm import MicroVMFactory


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="GDB requires a vmlinux but we ship a uImage for ARM in our CI",
)
def test_gdb_connects(guest_kernel_linux_6_1, rootfs):
    """Checks that GDB works in a FC VM"""

    bin_dir = host_tools.cargo_build.build_gdb()

    vmfcty = MicroVMFactory(bin_dir)
    kernel_dbg = guest_kernel_linux_6_1.parent / "debug" / guest_kernel_linux_6_1.name
    uvm = vmfcty.build(kernel_dbg, rootfs)
    uvm.spawn(validate_api=False)
    uvm.add_net_iface()
    uvm.basic_config()
    uvm.enable_gdb()

    chroot_gdb_socket = Path(uvm.jailer.chroot_path(), uvm.gdb_socket)

    gdb_commands = f"""
    target remote {chroot_gdb_socket}
    hbreak start_kernel
    # continue to start_kernel
    continue
    # continue boot until interrupted
    continue
    """

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".gdb", delete=False, prefix="fc_gdb_"
    ) as f:
        f.write(gdb_commands)
        gdb_script = f.name

    gdb_proc = subprocess.Popen(
        f"""
        until [ -S {chroot_gdb_socket} ]; do
            echo 'waiting for {chroot_gdb_socket}';
            sleep 1;
        done;
        gdb {kernel_dbg} -batch -x {gdb_script}
        """,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # start the VM and wait for it to be running
    uvm.start()

    # the VM started successfully, let's kill everything
    gdb_proc.terminate()
    os.kill(uvm.firecracker_pid, signal.SIGKILL)
    uvm.mark_killed()

    # verify that GDB hit the breakpoint on start_kernel
    stdout, stderr = gdb_proc.communicate(timeout=10)
    assert (
        "hit Breakpoint 1, start_kernel" in stdout
    ), f"Breakpoint wasn't hit:\nstdout:\n{stdout}\n\nstderr:\n{stderr}"
