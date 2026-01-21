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
