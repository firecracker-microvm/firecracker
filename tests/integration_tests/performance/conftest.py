# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for performance tests"""

import json

import pytest

from framework import defs, utils
from framework.properties import global_props


# pylint: disable=too-few-public-methods
class JsonFileDumper:
    """Class responsible with outputting test results to files."""

    def __init__(self, test_name):
        """Initialize the instance."""
        self._root_path = defs.TEST_RESULTS_DIR
        # Create the root directory, if it doesn't exist.
        self._root_path.mkdir(exist_ok=True)
        kv = utils.get_kernel_version(level=1)
        instance = global_props.instance
        self._results_file = (
            self._root_path / f"{test_name}_results_{instance}_{kv}.ndjson"
        )

    def dump(self, result):
        """Dump the results in JSON format."""
        with self._results_file.open("a", encoding="utf-8") as file_fd:
            json.dump(result, file_fd)
            file_fd.write("\n")  # Add newline cause Py JSON does not
            file_fd.flush()


@pytest.fixture
def results_file_dumper(request):
    """Dump results of performance test as a file"""
    # we want the test filename, like test_network_latency
    return JsonFileDumper(request.node.parent.path.stem)
