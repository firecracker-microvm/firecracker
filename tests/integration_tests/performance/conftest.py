# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Pytest fixtures and redefined-outer-name don't mix well. Disable it.
# pylint:disable=redefined-outer-name

"""Fixtures for performance tests"""

import json

import pytest

from framework import defs, utils
from framework.properties import global_props
from framework.stats import core


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


def send_metrics(metrics, stats: core.Core):
    """Extract metrics from a statistics run

    Also converts the units to CloudWatch-compatible ones.
    """
    unit_map = {
        "ms": "Milliseconds",
        "seconds": "Seconds",
        "Mbps": "Megabits/Second",
        "KiB/s": "Kilobytes/Second",
        "io/s": "Count/Second",
        "#": "Count",
        "percentage": "Percent",
    }

    results = stats.statistics["results"]
    for tag in results:
        dimensions = stats.custom.copy()
        # the last component of the tag is the test name
        # for example vmlinux-4.14.bin/ubuntu-18.04.ext4/2vcpu_1024mb.json/tcp-p1024K-ws16K-bd
        test = tag.split("/")[-1]
        dimensions["test"] = test
        dimensions["performance_test"] = stats.name
        metrics.set_dimensions(dimensions)
        metrics.set_property("tag", tag)

        for key, val in results[tag].items():
            for agg in val:
                if agg == "_unit":
                    continue
                metrics.put_metric(
                    f"{key}_{agg}", val[agg]["value"], unit=unit_map[val["_unit"]]
                )
        metrics.flush()


@pytest.fixture
def st_core(metrics, results_file_dumper, guest_kernel, rootfs, request):
    """Helper fixture to dump results and publish metrics"""
    stats = core.Core()
    guest_kernel_ver = guest_kernel.stem[2:]
    stats.check_baseline = request.config.getoption("--perf-fail")
    stats.env_id_prefix = f"{guest_kernel_ver}/{rootfs.name}"
    stats.iterations = 1
    stats.custom = {
        "instance": global_props.instance,
        "cpu_model": global_props.cpu_model,
        "host_kernel": "linux-" + global_props.host_linux_version,
        "guest_kernel": guest_kernel_ver,
        "rootfs": rootfs.name,
    }
    stats.metrics = metrics
    stats.metrics_test = request.function.__name__
    yield stats
    # If the test is skipped, there will be no results, so only dump if there
    # is some.
    if stats.statistics["results"]:
        results_file_dumper.dump(stats.statistics)
    send_metrics(metrics, stats)
