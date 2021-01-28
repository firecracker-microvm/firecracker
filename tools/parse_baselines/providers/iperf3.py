# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Implement the DataParser for iperf3 throughput tests."""

import json
import statistics
import math
from collections import defaultdict, Iterator
from typing import List
from providers.types import DataParser

# We add a small extra percentage margin, to account for small variations
# that were not caught while gathering baselines. This provides
# slightly better reliability, while not affecting regression
# detection.
DELTA_EXTRA_MARGIN = 3


def nested_dict():
    """Create an infinitely nested dictionary."""
    return defaultdict(nested_dict)


# pylint: disable=R0903
class Iperf3DataParser(DataParser):
    """Parse the data provided by the iperf3 throughput tests."""

    # pylint: disable=W0102
    def __init__(self, data_provider: Iterator):
        """Initialize the data parser."""
        self._data_provider = iter(data_provider)
        self._baselines_defs = [
            "throughput/total",
            "cpu_utilization_vcpus_total/value",
            "cpu_utilization_vmm/value",
        ]
        # This object will hold the parsed data.
        self._data = nested_dict()

    # pylint: disable=R0201
    def _calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""
        avg = statistics.mean(data)
        stddev = statistics.stdev(data)
        return {
            'target': math.ceil(round(avg, 2)),
            'delta_percentage':
                math.ceil(round(3 * stddev/avg * 100, 2)) + DELTA_EXTRA_MARGIN
        }

    def _format_baselines(self) -> List[dict]:
        """Return the computed baselines into the right serializable format."""
        baselines = dict()

        for cpu_model in self._data:
            baselines[cpu_model] = {
                'model': cpu_model, **self._data[cpu_model]}

        temp_baselines = baselines
        baselines = []

        for cpu_model in self._data:
            baselines.append(temp_baselines[cpu_model])

        return baselines

    def _populate_baselines(self, key, parent):
        """Traverse the data dict and compute the baselines."""
        # Initial case.
        if key is None:
            for k in parent:
                self._populate_baselines(k, parent)
            return

        # Base case, reached a data list.
        if isinstance(parent[key], list):
            parent[key] = self._calculate_baseline(parent[key])
            return

        # Recurse for all children.
        for k in parent[key]:
            self._populate_baselines(k, parent[key])

    def parse(self) -> dict:
        """Parse the rows and return baselines."""
        line = next(self._data_provider)
        while line:
            json_line = json.loads(line)
            measurements = json_line['results']
            cpu_model_name = json_line['custom']['cpu_model_name']

            # Consume the data and aggregate into lists.
            for tag in measurements.keys():
                for key in self._baselines_defs:
                    [ms_name, st_name] = key.split("/")
                    ms_data = measurements[tag].get(ms_name)

                    st_data = ms_data.get(st_name)

                    [kernel_version,
                     rootfs_type,
                     iperf_config] = tag.split("/")

                    data = self._data[cpu_model_name][ms_name]
                    data = data[kernel_version][rootfs_type][st_name]
                    if isinstance(data[iperf_config], list):
                        data[iperf_config].append(st_data)
                    else:
                        data[iperf_config] = [st_data]
            line = next(self._data_provider)

        self._populate_baselines(None, self._data)

        return self._format_baselines()
