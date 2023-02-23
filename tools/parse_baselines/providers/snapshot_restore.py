# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Implement the DataParser for snapshot restore performance tests."""

import math
import statistics
from collections.abc import Iterator
from typing import List

from providers.types import DataParser

# We add a small extra percentage margin, to account for small variations
# that were not caught while gathering baselines. This provides
# slightly better reliability, while not affecting regression
# detection.
DELTA_EXTRA_MARGIN = 6


# pylint: disable=R0903
class SnapshotRestoreDataParser(DataParser):
    """Parse the data provided by the snapshot restore performance tests."""

    # pylint: disable=W0102
    def __init__(self, data_provider: Iterator):
        """Initialize the data parser."""
        super().__init__(
            data_provider,
            [
                "latency/P50",
                "latency/P90",
            ],
        )

    def calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""
        avg = statistics.mean(data)
        min_ = min(data)
        max_ = max(data)

        min_delta = 100 * abs(avg - min_) / avg
        max_delta = 100 * abs(avg - max_) / avg
        delta = max(max_delta, min_delta)

        return {
            "target": round(avg, 3),
            "delta_percentage": math.ceil(delta) + DELTA_EXTRA_MARGIN,
        }
