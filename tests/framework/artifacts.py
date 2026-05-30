# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Define classes for interacting with CI artifacts"""

import re
from pathlib import Path
from typing import Iterator

import pytest

from framework.defs import ARTIFACT_DIR


def select_supported_kernels():
    """Select guest kernels supported by the current combination of kernel and
    instance type.
    """
    supported_kernels = [r"vmlinux-5.10.\d+", r"vmlinux-6.1.\d+"]

    # Booting with MPTable is deprecated but we still want to test
    # for it. Until we drop support for it we will be building a 5.10 guest
    # kernel without ACPI support, so that we are able to test this use-case
    # as well.
    # TODO: remove this once we drop support for MPTable
    supported_kernels.append(r"vmlinux-5.10.\d+-no-acpi")

    return supported_kernels


def kernels(glob, artifact_dir: Path = ARTIFACT_DIR) -> Iterator:
    """Return supported kernels as kernels supported by the current combination of kernel and
    instance type.
    """
    supported_kernels = select_supported_kernels()
    for kernel in sorted(artifact_dir.glob(glob)):
        for kernel_regex in supported_kernels:
            if re.fullmatch(kernel_regex, kernel.name):
                yield kernel
                break


def disks(glob) -> list:
    """Return supported rootfs"""
    return sorted(ARTIFACT_DIR.glob(glob))


def kernel_params(glob="vmlinux-*", select=kernels, artifact_dir=ARTIFACT_DIR) -> list:
    """Return supported kernels or a single None if no kernels are found"""
    return [
        pytest.param(kernel, id=kernel.name) for kernel in select(glob, artifact_dir)
    ] or [pytest.param(None, id="no-kernel-found")]


# Catalogues of guest kernel artifacts. Each entry is a `pytest.param` so test
# ids carry the kernel filename (e.g. "vmlinux-6.1.123") rather than "kernel0".
ALL_GUEST_KERNELS = list(kernel_params("vmlinux-*"))
ACPI_GUEST_KERNELS = [p for p in kernel_params("vmlinux-*") if "no-acpi" not in p.id]
GUEST_KERNELS_5_10 = list(kernel_params("vmlinux-5.10*"))
GUEST_KERNELS_6_1 = list(kernel_params("vmlinux-6.1*"))
GUEST_KERNELS_6_1_DEBUG = list(
    kernel_params("vmlinux-6.1*", artifact_dir=ARTIFACT_DIR / "debug")
)
# The single canonical kernel used when a test pins to one specific kernel
# (e.g. tests of Firecracker functionality that don't depend on guest kernel).
# Update here when the default version changes. Stored as a `pytest.param`
# so the test id carries the kernel filename (e.g. "vmlinux-6.1.168").
GUEST_KERNEL_DEFAULT = GUEST_KERNELS_6_1[0] if GUEST_KERNELS_6_1 else None
GUEST_KERNEL_DEFAULT_DEBUG = (
    GUEST_KERNELS_6_1_DEBUG[0] if GUEST_KERNELS_6_1_DEBUG else None
)


def pin_guest_kernel(kernels_or_path):
    """Convenience marker for pinning the `guest_kernel` dim.

    The default `guest_kernel` fixture parametrizes over ALL_GUEST_KERNELS;
    use this helper to restrict to a single kernel or a smaller subset.

    Usage at module level:
        pytestmark = pin_guest_kernel(ACPI_GUEST_KERNELS)

    Usage at test level:
        @pin_guest_kernel(GUEST_KERNEL_DEFAULT)
        def test_foo(uvm): ...

    Accepts a kernel catalogue (e.g. ACPI_GUEST_KERNELS), a single
    `pytest.param`, or a single Path.
    """
    # Wrap a single Path or pytest.param into a list. A bare ParameterSet
    # passed to `parametrize` would be treated as a sequence of args and
    # produce broken parameterizations.
    if not isinstance(kernels_or_path, list):
        kernels_or_path = [kernels_or_path]
    return pytest.mark.parametrize("guest_kernel", kernels_or_path, indirect=True)


def pin_rootfs_mode(mode):
    """Convenience marker for pinning the `rootfs_mode` dim ("ro" | "rw")."""
    return pytest.mark.parametrize("rootfs_mode", [mode], indirect=True)


def pin_pci(enabled):
    """Convenience marker for pinning the `pci_enabled` dim to a single value."""
    return pytest.mark.parametrize("pci_enabled", [enabled], indirect=True)
