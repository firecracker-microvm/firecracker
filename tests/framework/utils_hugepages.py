# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Huge page configuration and host capability helpers."""

from enum import Enum

from packaging import version

from framework.utils import get_kernel_version


def supports_hugetlbfs_discard():
    """Returns True if the kernel supports hugetlbfs discard"""
    return version.parse(get_kernel_version()) >= version.parse("5.18.0")


class HugePagesConfig(str, Enum):
    """Enum describing the huge pages configurations supported Firecracker"""

    NONE = "None"
    TRANSPARENT = "Transparent"
    HUGETLBFS_2MB = "2M"
