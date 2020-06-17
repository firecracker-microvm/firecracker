# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for snapshot testing."""
from framework.utils import run_cmd


# Merges layer on top of base.
def merge_memory_bitmaps(base, layer, block_size=4096):
    """Merge a sparse layer on top of base."""
    dd_command = 'dd bs={} if={} of={} conv=sparse,notrunc'
    dd_command = dd_command.format(block_size, layer, base)
    _ = run_cmd(dd_command)
