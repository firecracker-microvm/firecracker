#!/bin/env python3
# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Script used to calculate baselines from raw performance test output.

The script expects to find at least 2 files containing test results in
the provided data folder
  (e.g. test_results/test_vsock_throughput_results_m5d.metal_5.10.json).
"""

import argparse
import json
import re
from pathlib import Path

from providers.block import BlockDataParser
from providers.iperf3 import Iperf3DataParser
from providers.latency import LatencyDataParser
from providers.snapshot_restore import SnapshotRestoreDataParser

DATA_PARSERS = {
    "vsock_throughput": Iperf3DataParser,
    "network_tcp_throughput": Iperf3DataParser,
    "block_performance": BlockDataParser,
    "snapshot_restore_performance": SnapshotRestoreDataParser,
    "network_latency": LatencyDataParser,
}


def read_data_files(data_dir):
    """Return all JSON objects contained in the files of this dir, organized per test/instance/kv."""
    data_dir = Path(data_dir)
    assert data_dir.is_dir()
    data = {}
    # Get all files in the dir tree that match a test.
    for file in data_dir.rglob("*.ndjson"):
        match = re.search(
            "test_(?P<test>.+)_results_(?P<instance>.+)_(?P<kv>.+).ndjson",
            str(file.name),
        )
        test, instance, kv = match.groups()
        for line in file.open(encoding="utf-8"):
            data.setdefault((test, instance, kv), []).append(json.loads(line))
    return data


def overlay(dict_old, dict_new):
    """
    Overlay one dictionary on top of another

    >>> a = {'a': {'b': 1, 'c': 1}}
    >>> b = {'a': {'b': 2, 'd': 2}}
    >>> overlay(a, b)
    {'a': {'b': 2, 'c': 1, 'd': 2}}
    """
    res = dict_old.copy()
    for key, val in dict_new.items():
        if key in dict_old and isinstance(val, dict):
            res[key] = overlay(dict_old[key], dict_new[key])
        else:
            res[key] = val
    return res


def update_baseline(test, instance, kernel, test_data):
    """Parse and update the baselines"""
    baselines_path = Path(
        f"./tests/integration_tests/performance/configs/test_{test}_config_{kernel}.json"
    )
    json_baselines = json.loads(baselines_path.read_text("utf-8"))
    old_cpus = json_baselines["hosts"]["instances"][instance]["cpus"]

    # Instantiate the right data parser.
    parser = DATA_PARSERS[test](test_data)
    cpus = parser.parse()

    for cpu in cpus:
        model = cpu["model"]
        for old_cpu in old_cpus:
            if old_cpu["model"] == model:
                old_cpu["baselines"] = overlay(old_cpu["baselines"], cpu["baselines"])

    baselines_path.write_text(
        json.dumps(json_baselines, indent=4, sort_keys=True), encoding="utf-8"
    )

    # Warn against the fact that not all CPUs pertaining to
    # some arch were updated.
    assert len(cpus) == len(old_cpus), (
        "It may be that only a subset of CPU types were updated! "
        "Need to run again! Nevertheless we updated the baselines..."
    )


def main():
    """Run the main logic"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-d",
        "--data-folder",
        help="Path to folder containing raw test data.",
        required=True,
    )
    args = parser.parse_args()
    data = read_data_files(args.data_folder)
    for test, instance, kv in data:
        test_data = data[test, instance, kv]
        update_baseline(test, instance, kv, test_data)


if __name__ == "__main__":
    main()
