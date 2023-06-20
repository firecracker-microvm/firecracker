# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all unit tests pass at integration time."""

import os
import logging
import json
import shutil
import platform
from pathlib import Path

import pytest

from framework import utils
from framework.defs import FC_WORKSPACE_DIR
from host_tools import proc

BENCHMARK_DIRECTORY = "{}/src/vmm".format(FC_WORKSPACE_DIR)
DEFAULT_BUILD_TARGET = "{}-unknown-linux-musl".format(platform.machine())

PROC_MODEL = proc.proc_type()

NSEC_IN_MSEC = 1000000

BASELINES = {
    "Intel": {
        "serialize": {
            "no-crc": {"target": 0.205, "delta": 0.050},  # milliseconds  # milliseconds
            "crc": {"target": 0.244, "delta": 0.44},  # milliseconds  # milliseconds
        },
        "deserialize": {
            "no-crc": {"target": 0.056, "delta": 0.02},  # milliseconds  # milliseconds
            "crc": {"target": 0.075, "delta": 0.030},  # milliseconds  # milliseconds
        },
    },
    "AMD": {
        "serialize": {
            "no-crc": {"target": 0.084, "delta": 0.05},  # milliseconds  # milliseconds
            "crc": {"target": 0.108, "delta": 0.025},  # milliseconds  # milliseconds
        },
        "deserialize": {
            "no-crc": {"target": 0.030, "delta": 0.02},  # milliseconds  # milliseconds
            "crc": {"target": 0.052, "delta": 0.04},  # milliseconds  # milliseconds
        },
    },
    "ARM": {
        "serialize": {
            "no-crc": {"target": 0.050, "delta": 0.03},  # milliseconds  # milliseconds
            "crc": {"target": 0.050, "delta": 0.025},  # milliseconds  # milliseconds
        },
        "deserialize": {
            "no-crc": {"target": 0.031, "delta": 0.02},  # milliseconds  # milliseconds
            "crc": {"target": 0.038, "delta": 0.02},  # milliseconds  # milliseconds
        },
    },
}


def _check_statistics(directory, mean):
    proc_model = [item for item in BASELINES if item in PROC_MODEL]
    assert len(proc_model) == 1, "Could not get processor model!"

    if "deserialize" in directory.lower():
        bench = "deserialize"
    else:
        bench = "serialize"

    if "crc" in directory.lower():
        attribute = "crc"
    else:
        attribute = "no-crc"

    measure = BASELINES[proc_model[0]][bench][attribute]
    target, delta = measure["target"], measure["delta"]
    assert target == pytest.approx(
        mean, abs=delta, rel=1e-6
    ), f"Benchmark result {directory} has changed!"

    return f"{target - delta} <= result <= {target + delta}"


def test_serialization_benchmark(monkeypatch, record_property):
    """
    Benchmark test for MicrovmState serialization/deserialization.

    @type: performance
    """
    logger = logging.getLogger("serialization_benchmark")

    # Move into the benchmark directory
    monkeypatch.chdir(BENCHMARK_DIRECTORY)

    # Run benchmark test
    cmd = "cargo bench --target {}".format(DEFAULT_BUILD_TARGET)
    result = utils.run_cmd_sync(cmd)
    assert result.returncode == 0

    # Parse each Criterion benchmark from the result folder and
    # check the results against a baseline
    results_dir = Path(FC_WORKSPACE_DIR) / "build/vmm_benchmark"
    for directory in os.listdir(results_dir):
        # Ignore the 'report' directory as it is of no use to us
        if directory == "report":
            continue

        logger.info("Benchmark: %s", directory)

        # Retrieve the 'estimates.json' file content
        json_file = results_dir / directory / "base/estimates.json"
        estimates = json.loads(json_file.read_text())

        # Save the Mean measurement(nanoseconds) and transform it(milliseconds)
        mean = estimates["mean"]["point_estimate"] / NSEC_IN_MSEC
        logger.info("Mean: %f", mean)

        criteria = _check_statistics(directory, mean)
        record_property(f"{directory}_ms", mean)
        record_property(f"{directory}_criteria", criteria)

    # Cleanup the Target directory
    shutil.rmtree(results_dir)
