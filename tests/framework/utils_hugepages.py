# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Huge pages configuration for microVMs."""

from enum import Enum


class HugePagesConfig(str, Enum):
    """Enum describing the huge pages configurations supported Firecracker"""

    NONE = "None"
    TRANSPARENT = "Transparent"
    HUGETLBFS_2MB = "2M"
