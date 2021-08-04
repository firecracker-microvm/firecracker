# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all unit tests pass at integration time."""

import platform
import os
import logging
import json
import shutil

import pytest
import framework.utils as utils
import host_tools.proc as proc
from framework.defs import FC_WORKSPACE_DIR

BENCHMARK_DIRECTORY = "{}/src/vmm".format(FC_WORKSPACE_DIR)

PROC_MODEL = proc.proc_type()

NSEC_IN_MSEC = 1000000

BASELINES = {
    "Intel": {
        "serialize": {
            "no-crc": {
                "target": 0.146,  # milliseconds
                "delta": 0.025  # milliseconds
            },
            "crc": {
                "target": 0.213,  # milliseconds
                "delta": 0.025  # milliseconds
            }
        },
        "deserialize": {
            "no-crc": {
                "target": 0.034,  # milliseconds
                "delta": 0.015  # milliseconds
            },
            "crc": {
                "target": 0.042,  # milliseconds
                "delta": 0.015  # milliseconds
            }
        }
    },
    "AMD": {
        "serialize": {
            "no-crc": {
                "target": 0.096,  # milliseconds
                "delta": 0.025  # milliseconds
            },
            "crc": {
                "target": 0.122,  # milliseconds
                "delta": 0.025  # milliseconds
            }
        },
        "deserialize": {
            "no-crc": {
                "target": 0.034,  # milliseconds
                "delta": 0.015  # milliseconds
            },
            "crc": {
                "target": 0.042,  # milliseconds
                "delta": 0.015  # milliseconds
            }
        }
    },
    "ARM": {
        "serialize": {
            "no-crc": {
                "target": 0.096,  # milliseconds
                "delta": 0.025  # milliseconds
            },
            "crc": {
                "target": 0.186,  # milliseconds
                "delta": 0.025  # milliseconds
            }
        },
        "deserialize": {
            "no-crc": {
                "target": 0.034,  # milliseconds
                "delta": 0.015  # milliseconds
            },
            "crc": {
                "target": 0.042,  # milliseconds
                "delta": 0.015  # milliseconds
            }
        }
    }
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
    low = measure["target"] - measure["delta"]
    high = measure["target"] + measure["delta"]
    assert low <= mean <= high, "Benchmark result {} has changed!" \
        .format(directory)

    return directory, f"{mean} ms", f"{low} <= result <= {high}"


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_serialization_benchmark():
    """
    Benchmark test for MicrovmState serialization/deserialization.

    @type: performance
    """
    logger = logging.getLogger("serialization_benchmark")

    # Move into the benchmark directory
    os.chdir(BENCHMARK_DIRECTORY)

    # Run benchmark test
    cmd = 'cargo bench'
    result = utils.run_cmd_sync(cmd)
    assert result.returncode == 0

    results_and_criteria = ["", ""]

    # Parse each Criterion benchmark from the result folder and
    # check the results against a baseline
    results_dir = os.path.join(FC_WORKSPACE_DIR, "build/vmm_benchmark")
    for directory in os.listdir(results_dir):
        # Ignore the 'report' directory as it is of no use to us
        if directory == "report":
            continue

        logger.info("Benchmark: %s", directory)

        # Retrieve the 'estimates.json' file content
        json_file = os.path.join(
            results_dir,
            "{}/{}".format(directory, "base/estimates.json"))
        with open(json_file, "r") as read_file:
            estimates = json.load(read_file)

        # Save the Mean measurement(nanoseconds) and transform it(milliseconds)
        mean = estimates['mean']['point_estimate'] / NSEC_IN_MSEC
        logger.info("Mean: %f", mean)

        res = _check_statistics(directory, mean)

        results_and_criteria[0] += f"{res[0]}: {res[1]}, "
        results_and_criteria[1] += f"{res[0]}: {res[2]}, "

    # Cleanup the Target directory
    shutil.rmtree(results_dir)

    # Return pretty formatted data for the test report.
    return results_and_criteria[0], results_and_criteria[1]
