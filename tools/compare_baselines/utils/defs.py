# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Some common definitions used in different modules"""


# fmt: off
CODENAME2DICT = {
    "skylake": {
        "instance": "m5d.metal",
        "model": "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
    },
    "cascadelake": {
        "instance": "m5d.metal",
        "model": "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
    },
    "icelake": {
        "instance": "m6i.metal",
        "model": "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz",
    },
    "milan": {
        "instance": "m6a.metal",
        "model": "AMD EPYC 7R13 48-Core Processor"
    },
    "graviton2": {
        "instance": "m6g.metal",
        "model": "ARM_NEOVERSE_N1"
    },
    "graviton3": {
        "instance": "c7g.metal",
        "model": "ARM_NEOVERSE_V1"
    },
}
# fmt: on

MODEL2SHORT = {
    "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz": "m5d/SL",
    "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz": "m5d/CL",
    "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz": "m6i",
    "AMD EPYC 7R13 48-Core Processor": "m6a",
    "ARM_NEOVERSE_N1": "m6g",
    "ARM_NEOVERSE_V1": "c7g",
}

DEFAULT_BASELINE_DIRECTORY = "tests/integration_tests/performance/configs/"

BASELINE_FILENAME_PATTERN = r"^test_(.+)_config_(.+).json"

BASELINE_FILENAME_FORMAT = "test_{test}_config_{kernel}.json"

DEFAULT_RESULT_FILEPATH = "comparison_result.json"

TESTS = [
    "block_performance",
    "network_latency",
    "network_tcp_throughput",
    "snapshot_restore_performance",
    "vsock_throughput",
]

KERNELS = [
    "4.14",
    "5.10",
    "6.1",
]
