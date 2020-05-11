# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Holds statistics for a given metric."""

class Statistics:
    """Holds results from multiple runs of the same test."""

    def __init__(self):
        """Initialize variables used to compute statistics."""
        self.values = []
        self.count = 0
        self.dev = 0
        self.mean = self.min = self.max = self.median = 0

    def add(self, value):
        """Add an observed value to the list."""
        self.values.append(value)
        self.count += 1

    def compute_stats(self):
        """Compute the statistics on the given data."""
        self.mean = statistics.mean(self.values)
        self.median = statistics.median(self.values)
        self.dev = statistics.stdev(self.values)
        self.min = min(self.values)
        self.max = max(self.values)
