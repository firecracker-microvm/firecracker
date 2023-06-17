# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Implement the DataParser for block device performance tests."""

import math
import statistics
from collections.abc import Iterator
from typing import List

from providers.types import DataParser

# We add a small extra percentage margin, to account for small variations
# that were not caught while gathering baselines. This provides
# slightly better reliability, while not affecting regression
# detection.
DELTA_EXTRA_MARGIN = 4


# pylint: disable=R0903
class BlockDataParser(DataParser):
    """Parse the data provided by the block performance tests."""

    # pylint: disable=W0102
    def __init__(self, data_provider: Iterator):
        """Initialize the data parser."""
        super().__init__(
            data_provider,
            [
                "iops_read/Avg",
                "iops_write/Avg",
                "bw_read/Avg",
                "bw_write/Avg",
                "cpu_utilization_vcpus_total/Avg",
                "cpu_utilization_vmm/Avg",
            ],
        )

    def calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""
        avg = statistics.mean(data)
        stddev = statistics.stdev(data)
        return {
            "target": math.ceil(round(avg, 2)),
            "delta_percentage": math.ceil(3 * stddev / avg * 100) + DELTA_EXTRA_MARGIN,
        }
