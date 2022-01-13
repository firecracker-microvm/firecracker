# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Implement the DataParser for snapshot restore performance tests."""

import statistics
import math
from collections.abc import Iterator
from typing import List
from providers.types import DataParser

# We add a small extra percentage margin, to account for small variations
# that were not caught while gathering baselines. This provides
# slightly better reliability, while not affecting regression
# detection.
DELTA_EXTRA_MARGIN = 4


# pylint: disable=R0903
class SnapshotRestoreDataParser(DataParser):
    """Parse the data provided by the snapshot restore performance tests."""

    # pylint: disable=W0102
    def __init__(self, data_provider: Iterator):
        """Initialize the data parser."""
        super().__init__(data_provider, [
            "restore_latency/P50",
            "restore_latency/P90",
        ])

    # pylint: disable=R0201
    def calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""
        avg = statistics.mean(data)
        stddev = statistics.stdev(data)
        return {
            'target': math.ceil(round(avg, 2)),
            'delta_percentage':
                math.ceil(3 * stddev/avg * 100) + DELTA_EXTRA_MARGIN
        }
