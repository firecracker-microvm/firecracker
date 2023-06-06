# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A benchmark that checks for regression of CPU template operations."""

import json
import logging
import os
import platform
import shutil
from pathlib import Path

from framework import utils
from framework.defs import FC_WORKSPACE_DIR
from host_tools import proc

BENCHMARK_DIRECTORY = "{}/src/vmm".format(FC_WORKSPACE_DIR)
DEFAULT_BUILD_TARGET = "{}-unknown-linux-musl".format(platform.machine())

PROC_MODEL = proc.proc_type()

NSEC_IN_MSEC = 1000000

BASELINES = {
    "Intel": {
        "deserialize": {"max_target": 0.02},  # milliseconds
        "serialize": {"max_target": 0.02},  # milliseconds
    },
    "AMD": {
        "deserialize": {"max_target": 0.02},  # milliseconds
        "serialize": {"max_target": 0.02},  # milliseconds
    },
    "ARM": {
        "deserialize": {"max_target": 0.006},  # milliseconds
        "serialize": {"max_target": 0.006},  # milliseconds
    },
}


def _check_statistics(directory, mean):
    proc_model = [item for item in BASELINES if item in PROC_MODEL]
    assert len(proc_model) == 1, "Could not get processor model!"

    if "deserialize" in directory.lower():
        bench = "deserialize"
    else:
        bench = "serialize"

    measure = BASELINES[proc_model[0]][bench]
    max_target = measure["max_target"]

    # When using multiple data sets where the delta can
    # vary substantially, consider making use of the
    # 'rel' parameter for more flexibility.
    assert mean < max_target, f"Benchmark result {directory} has changed!"

    return f"{max_target} > result"


def test_cpu_template_benchmark(monkeypatch, record_property):
    """
    Benchmark test for CpuTemplate deserialization.
    """
    logger = logging.getLogger("cpu_template_benchmark")

    # Move into the benchmark directory
    monkeypatch.chdir(BENCHMARK_DIRECTORY)

    # Run benchmark test
    cmd = "cargo bench --bench cpu_templates --target {}".format(DEFAULT_BUILD_TARGET)
    result = utils.run_cmd_sync(cmd)
    assert result.returncode == 0

    # Parse each Criterion benchmark from the result folder and
    # check the results against a baseline
    results_dir = Path(FC_WORKSPACE_DIR) / "build/vmm_benchmark/cpu_templates"
    for directory in os.listdir(results_dir):
        # Ignore the 'report' directory as it is of no use to us
        if directory == "report":
            continue

        logger.info("Benchmark: %s", directory)

        # Retrieve the 'estimates.json' file content
        json_file = results_dir / directory / "base/estimates.json"
        estimates = json.loads(json_file.read_text())

        # Save the Mean measurement(nanoseconds) and transform it(milliseconds)
        mean_ns = estimates["mean"]["point_estimate"]
        mean_ms = mean_ns / NSEC_IN_MSEC
        logger.info("Mean: [%f milliseconds], [%f nanoseconds]", mean_ms, mean_ns)

        criteria = _check_statistics(directory, mean_ms)
        record_property(f"{directory}_ms", mean_ms)
        record_property(f"{directory}_criteria", criteria)

    # Cleanup the Target directory
    shutil.rmtree(results_dir)
