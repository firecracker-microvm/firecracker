# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define data types and abstractions for parsers."""

from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterator
from typing import List

# pylint: disable=R0903


def nested_dict():
    """Create an infinitely nested dictionary."""
    return defaultdict(nested_dict)


class DataParser(ABC):
    """Abstract class to be used for baselines extraction."""

    def __init__(self, data_provider: Iterator, baselines_defs):
        """Initialize the data parser."""
        self._data_provider = iter(data_provider)
        self._baselines_defs = baselines_defs
        # This object will hold the parsed data.
        self._data = nested_dict()

    @abstractmethod
    def calculate_baseline(self, data: List[float]) -> dict:
        """Return the target and delta values, given a list of data points."""

    def _format_baselines(self) -> List[dict]:
        """Return the computed baselines into the right serializable format."""
        baselines = {}

        for cpu_model in self._data:
            baselines[cpu_model] = {
                "model": cpu_model,
                "baselines": self._data[cpu_model],
            }

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
            parent[key] = self.calculate_baseline(parent[key])
            return

        # Recurse for all children.
        for k in parent[key]:
            self._populate_baselines(k, parent[key])

    def parse(self) -> dict:
        """Parse the rows and return baselines."""
        for row in self._data_provider:
            measurements = row["results"]
            cpu_model = row["custom"]["cpu_model"]
            # Consume the data and aggregate into lists.
            for tag in measurements.keys():
                for key in self._baselines_defs:
                    [ms_name, st_name] = key.split("/")
                    ms_data = measurements[tag].get(ms_name)

                    if ms_data is None:
                        continue

                    st_data = ms_data.get(st_name)["value"]

                    [
                        kernel_version,
                        rootfs_type,
                        microvm_config,
                        test_config,
                    ] = tag.split("/")

                    data = self._data[cpu_model][ms_name]
                    data = data[kernel_version][rootfs_type]
                    data = data[microvm_config][st_name]
                    if isinstance(data[test_config], list):
                        data[test_config].append(st_data)
                    else:
                        data[test_config] = [st_data]

        self._populate_baselines(None, self._data)

        return self._format_baselines()
