# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script used to calculate baselines from raw performance test output."""

# We need to call sys.path.append(os.path.join(os.getcwd(), 'tests'))
# before importing SUPPORTED_KERNELS. But this results in a pyling error.
# pylint: disable=wrong-import-position

import argparse
import os
import tempfile
import json
from typing import List
import sys

from providers.types import FileDataProvider
from providers.iperf3 import Iperf3DataParser
from providers.block import BlockDataParser
from providers.snapshot_restore import SnapshotRestoreDataParser
from providers.latency import LatencyDataParser

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


def get_data_files(args) -> List[str]:
    """Return a list of files that contain results for this test."""
    assert os.path.isdir(args.data_folder)

    file_list = []
    res_files = [
        f"{filename}_results_{args.kernel}.json"
        for filename in OUTPUT_FILENAMES[args.test]
    ]
    # Get all files in the dir tree that have the right name.
    for root, _, files in os.walk(args.data_folder):
        for file in files:
            if file in res_files:
                file_list.append(os.path.join(root, file))

    # We need at least one file.
    assert len(file_list) > 0

    return file_list


def concatenate_data_files(data_files: List[str]):
    """Create temp file to hold all concatenated results for this test."""
    outfile = tempfile.NamedTemporaryFile()

    for filename in data_files:
        with open(filename, encoding="utf-8") as infile:
            contents = str.encode(infile.read())
            outfile.write(contents)
    outfile.flush()
    return outfile


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
        choices=[
            "block_performance",
            "network_latency",
            "network_tcp_throughput",
            "snap_restore_performance",
            "vsock_throughput",
        ],
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
        choices=["m5d.metal", "m6i.metal", "m6a.metal", "m6g.metal"],
        required=True,
    )
    args = parser.parse_args()

    # Create the concatenated data file.
    data_file = concatenate_data_files(get_data_files(args))

    # Instantiate a file data provider.
    data_provider = FileDataProvider(data_file.name)

    # Instantiate the right data parser.
    parser = DATA_PARSERS[args.test](data_provider)

    # Finally, parse and update the baselines.
    with open(
        f"./tests/integration_tests/performance/configs/"
        f"test_{args.test}_config_{args.kernel}.json",
        "r+",
        encoding="utf8",
    ) as baselines_file:
        json_baselines = json.load(baselines_file)
        current_cpus = json_baselines["hosts"]["instances"][args.instance]["cpus"]
        cpus = parser.parse()

        for cpu in cpus:
            model = cpu["model"]
            for old_cpu in current_cpus:
                if old_cpu["model"] == model:
                    old_cpu["baselines"] = cpu["baselines"]
        baselines_file.truncate(0)
        baselines_file.seek(0, 0)
        json.dump(json_baselines, baselines_file, indent=4)

        # Warn against the fact that not all CPUs pertaining to
        # some arch were updated.
        assert len(cpus) == len(current_cpus), (
            "It may be that only a subset of CPU types were updated! "
            "Need to run again! Nevertheless we updated the baselines..."
        )


if __name__ == "__main__":
    main()
