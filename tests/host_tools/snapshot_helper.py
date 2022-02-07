# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for snapshot testing."""
from host_tools.cargo_build import run_rebase_snap_bin


# Merges layer on top of base.
def merge_memory_bitmaps(base, layer):
    """Merge a sparse layer on top of base."""
    run_rebase_snap_bin(base, layer)
