# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify 64 KiB base pages with the ARM64 Linux 6.1 and 6.18 kernels."""

import platform

import pytest

from framework.artifacts import GUEST_KERNELS_64K, pin_guest_kernel


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="64 KiB guest kernels require aarch64",
)
@pin_guest_kernel(GUEST_KERNELS_64K)
def test_guest_kernel_64k_page_size(uvm_booted):
    """Boot each non-debug 64 KiB kernel and query its page size over SSH."""
    _, stdout, _ = uvm_booted.ssh.check_output("getconf PAGE_SIZE")
    assert stdout.strip() == "65536"
