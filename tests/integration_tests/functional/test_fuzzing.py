# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures the fuzzing feature warning appears at startup."""

import host_tools.cargo_build
from framework.microvm import MicroVMFactory


def test_fuzzing_warning(guest_kernel, rootfs):
    """Checks that a Firecracker binary built with fuzzing logs a warning at startup"""

    bin_dir = host_tools.cargo_build.build_fuzzing()

    vmfcty = MicroVMFactory(bin_dir)
    uvm = vmfcty.build(guest_kernel, rootfs)
    uvm.spawn()
    uvm.basic_config()
    uvm.start()

    assert (
        "built with the `fuzzing` feature enabled" in uvm.log_data
    ), f"Fuzzing warning not found in logs:\n{uvm.log_data}"
    assert (
        "+fuzzing" in uvm.log_data
    ), f"Version string missing +fuzzing suffix:\n{uvm.log_data}"


def test_no_fuzzing_warning(uvm_plain):
    """Checks that a standard Firecracker binary does not log the fuzzing warning"""

    uvm_plain.spawn()
    uvm_plain.basic_config()
    uvm_plain.start()

    assert (
        "built with the `fuzzing` feature enabled" not in uvm_plain.log_data
    ), f"Fuzzing warning unexpectedly found in logs:\n{uvm_plain.log_data}"
