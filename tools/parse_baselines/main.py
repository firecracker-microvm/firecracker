# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script used to calculate baselines from raw performance test output."""

# We need to call sys.path.append(os.path.join(os.getcwd(), 'tests'))
# before importing SUPPORTED_KERNELS. But this results in a pyling error.
# pylint: disable=wrong-import-position

import argparse
import json
import os
import sys
from pathlib import Path

from providers.block import BlockDataParser
from providers.iperf3 import Iperf3DataParser
from providers.latency import LatencyDataParser
from providers.snapshot_restore import SnapshotRestoreDataParser

sys.path.append(os.path.join(os.getcwd(), "tests"))

from framework.defs import SUPPORTED_KERNELS  # noqa: E402

OUTPUT_FILENAMES = {
    "vsock_throughput": ["test_vsock_throughput"],
    "network_tcp_throughput": ["test_network_tcp_throughput"],
    "block_performance": [
        "test_block_performance_sync",
        "test_block_performance_async",
    ],
    "snap_restore_performance": ["test_snap_restore_performance"],
    "network_latency": ["test_network_latency"],
}

DATA_PARSERS = {
    "vsock_throughput": Iperf3DataParser,
    "network_tcp_throughput": Iperf3DataParser,
    "block_performance": BlockDataParser,
    "snap_restore_performance": SnapshotRestoreDataParser,
    "network_latency": LatencyDataParser,
}

TESTS = [
    "block_performance",
    "network_latency",
    "network_tcp_throughput",
    "snap_restore_performance",
    "vsock_throughput",
]

INSTANCES = ["m5d.metal", "m6i.metal", "m6a.metal", "m6g.metal", "c7g.metal"]


def read_data_files(args):
    """Return all JSON objects contained in the files for this test."""
    assert os.path.isdir(args.data_folder)

    res_files = [
        f"{filename}_results_{args.kernel}.json"
        for filename in OUTPUT_FILENAMES[args.test]
    ]
    # Get all files in the dir tree that have the right name.
    root_path = Path(args.data_folder)
    for root, _, files in os.walk(root_path):
        for file in files:
            if file in res_files:
                for line in open(Path(root) / file, encoding="utf-8"):
                    yield json.loads(line)


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


def main():
    """Run the main logic.

    This script needs to be run from Firecracker's root since
    it depends on functionality found in tests/ framework.
    The script expects to find at least 2 files containing test results in
    the provided data folder
     (e.q test_results/buildX/test_vsock_throughput_results_5.10.json).
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--data-folder",
        help="Path to folder containing raw test data.",
        action="store",
        required=True,
    )
    parser.add_argument(
        "-t",
        "--test",
        help="Performance test for which baselines \
                            are calculated.",
        action="store",
        choices=TESTS,
        required=True,
    )
    parser.add_argument(
        "-k",
        "--kernel",
        help="Host kernel version on which baselines \
                            are obtained.",
        action="store",
        choices=SUPPORTED_KERNELS,
        required=True,
    )
    parser.add_argument(
        "-i",
        "--instance",
        help="Instance type on which the baselines \
                            were obtained.",
        action="store",
        choices=INSTANCES,
        required=True,
    )
    args = parser.parse_args()

    # Instantiate the right data parser.
    parser = DATA_PARSERS[args.test](read_data_files(args))

    # Finally, parse and update the baselines.
    baselines_path = Path(
        f"./tests/integration_tests/performance/configs/test_{args.test}_config_{args.kernel}.json"
    )
    json_baselines = json.loads(baselines_path.read_text("utf-8"))
    current_cpus = json_baselines["hosts"]["instances"][args.instance]["cpus"]
    cpus = parser.parse()

    for cpu in cpus:
        model = cpu["model"]
        for old_cpu in current_cpus:
            if old_cpu["model"] == model:
                old_cpu["baselines"] = overlay(old_cpu["baselines"], cpu["baselines"])

    baselines_path.write_text(
        json.dumps(json_baselines, indent=4, sort_keys=True), encoding="utf-8"
    )

    # Warn against the fact that not all CPUs pertaining to
    # some arch were updated.
    assert len(cpus) == len(current_cpus), (
        "It may be that only a subset of CPU types were updated! "
        "Need to run again! Nevertheless we updated the baselines..."
    )


if __name__ == "__main__":
    main()
