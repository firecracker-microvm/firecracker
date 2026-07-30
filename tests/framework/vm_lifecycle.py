# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Lifecycle dimension for pytest microVM fixtures."""

from enum import Enum


class VmLifecycle(str, Enum):
    """End states supplied by the ``uvm_lifecycle`` dimension."""

    BOOTED = "booted"
    RESTORED = "restored"

    def __str__(self):
        """Return the stable value used in pytest IDs and reports."""
        return self.value
