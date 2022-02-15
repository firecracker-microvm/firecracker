# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script used to calculate baselines from raw performance test output."""

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
from framework.defs import SUPPORTED_KERNELS
from framework.utils import get_kernel_version

sys.path.append(os.path.join(os.getcwd(), 'tests'))


OUTPUT_FILENAMES = {
    'vsock_throughput': 'test_vsock_throughput',
    'network_tcp_throughput': 'test_network_tcp_throughput',
    'block_performance': 'test_block_performance',
    'snapshot_restore_performance': 'test_snap_restore_performance'
}

DATA_PARSERS = {
    'vsock_throughput': Iperf3DataParser,
    'network_tcp_throughput': Iperf3DataParser,
    'block_performance': BlockDataParser,
    'snapshot_restore_performance': SnapshotRestoreDataParser,
}


def get_data_files(args) -> List[str]:
    """Return a list of files that contain results for this test."""
    assert os.path.isdir(args.data_folder)

    file_list = []
    host_version = get_kernel_version(level=1)
    res_file = f"{OUTPUT_FILENAMES[args.test]}_results_{host_version}.json"
    # Get all files in the dir tree that have the right name.
    for root, _, files in os.walk(args.data_folder):
        for file in files:
            if file == res_file:
                file_list.append(os.path.join(root, file))

    # We need at least one file.
    assert len(file_list) > 0

    return file_list


def concatenate_data_files(data_files: List[str]):
    """Create temp file to hold all concatenated results for this test."""
    outfile = tempfile.NamedTemporaryFile()

    for filename in data_files:
        with open(filename, encoding='utf-8') as infile:
            outfile.write(str.encode(infile.read()))

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
    parser.add_argument("-d", "--data-folder",
                        help="Path to folder containing raw test data.",
                        action="store",
                        required=True)
    parser.add_argument("-t", "--test",
                        help="Performance test for which baselines \
                            are calculated.",
                        action="store",
                        choices=['vsock_throughput',
                                 'network_tcp_throughput',
                                 'block_performance',
                                 'snapshot_restore_performance'],
                        required=True)
    parser.add_argument("-k", "--kernel",
                        help="Host kernel version on which baselines \
                            are obtained.",
                        action="store",
                        choices=SUPPORTED_KERNELS,
                        required=True)
    args = parser.parse_args()

    # Create the concatenated data file.
    data_file = concatenate_data_files(get_data_files(args))

    # Instantiate a file data provider.
    data_provider = FileDataProvider(data_file.name)

    # Instantiate the right data parser.
    parser = DATA_PARSERS[args.test](data_provider)

    # Finally, parse and print the baselines.
    print(json.dumps(parser.parse(), indent=4))


if __name__ == "__main__":
    main()
