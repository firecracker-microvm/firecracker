# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Implement the DataParser for iperf3 throughput tests."""

import statistics
import math
from collections.abc import Iterator
from typing import List
from providers.types import DataParser

# We add a small extra percentage margin, to account for small variations
# that were not caught while gathering baselines. This provides
# slightly better reliability, while not affecting regression
# detection.
DELTA_EXTRA_MARGIN = 3


# pylint: disable=R0903
class Iperf3DataParser(DataParser):
    """Parse the data provided by the iperf3 throughput tests."""

    # pylint: disable=W0102
    def __init__(self, data_provider: Iterator):
        """Initialize the data parser."""
        super().__init__(data_provider, [
            "throughput/total",
            "cpu_utilization_vcpus_total/Avg",
            "cpu_utilization_vmm/Avg",
        ])

    # pylint: disable=R0201
    def calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""
        avg = statistics.mean(data)
        stddev = statistics.stdev(data)
        return {
            'target': math.ceil(round(avg, 2)),
            'delta_percentage':
                math.ceil(round(3 * stddev/avg * 100, 2)) + DELTA_EXTRA_MARGIN
        }
