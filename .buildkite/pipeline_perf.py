#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite performance pipelines dynamically"""

# pylint: disable=invalid-name

import os

from common import BKPipeline

# In `devtool_opts`, we restrict both the set of CPUs on which the docker container's threads can run,
# and its memory node. For the cpuset, we pick a continuous set of CPUs from a single NUMA node
# that is large enough so that every firecracker thread can get its own core. We exclude core #0, as
# the operating system sometimes uses it for book-keeping tasks. The memory node (-m parameter)
# has to be the node associated with the NUMA node from which we picked CPUs.
perf_test = {
    "virtio-block": {
        "label": "💿 Virtio Block Performance",
        "test_path": "integration_tests/performance/test_block_ab.py::test_block_performance",
        "devtool_opts": "-c 1-10 -m 0",
    },
    "vhost-user-block": {
        "label": "💿 vhost-user Block Performance",
        "test_path": "integration_tests/performance/test_block_ab.py::test_block_vhost_user_performance",
        "devtool_opts": "-c 1-10 -m 0",
        "ab_opts": "--noise-threshold 0.1",
    },
    "network-latency": {
        "label": "📠 Network Latency",
        "test_path": "integration_tests/performance/test_network_ab.py::test_network_latency",
        "devtool_opts": "-c 1-10 -m 0",
        # Triggers if delta is > 0.01ms (10µs) or default relative threshold (5%)
        "ab_opts": "--absolute-strength 0.010",
    },
    "network-throughput": {
        "label": "📠 Network TCP Throughput",
        "test_path": "integration_tests/performance/test_network_ab.py::test_network_tcp_throughput",
        "devtool_opts": "-c 1-10 -m 0",
    },
    "snapshot-latency": {
        "label": "📸 Snapshot Latency",
        "test_path": "integration_tests/performance/test_snapshot_ab.py",
        "devtool_opts": "-c 1-12 -m 0",
    },
    "vsock-throughput": {
        "label": "🧦 Vsock Throughput",
        "test_path": "integration_tests/performance/test_vsock_ab.py",
        "devtool_opts": "-c 1-10 -m 0",
    },
    "memory-overhead": {
        "label": "💾 Memory Overhead and 👢 Boottime",
        "test_path": "integration_tests/performance/test_memory_overhead.py integration_tests/performance/test_boottime.py::test_boottime",
        "devtool_opts": "-c 1-10 -m 0",
    },
}

REVISION_A = os.environ.get("REVISION_A")
REVISION_B = os.environ.get("REVISION_B")

# Either both are specified or neither. Only doing either is a bug. If you want to
# run performance tests _on_ a specific commit, specify neither and put your commit
# into buildkite's "commit" field.
assert (REVISION_A and REVISION_B) or (not REVISION_A and not REVISION_B)

BKPipeline.parser.add_argument(
    "--test",
    choices=list(perf_test.keys()),
    required=False,
    help="performance test",
    action="append",
)

retry = {}
if REVISION_A:
    # Enable automatic retry and disable manual retries to suppress spurious issues.
    retry["automatic"] = [
        {"exit_status": -1, "limit": 1},
        {"exit_status": 1, "limit": 1},
    ]
    retry["manual"] = False

pipeline = BKPipeline(
    # Boost priority from 1 to 2 so these jobs are preferred by ag=1 agents
    priority=2,
    # use ag=1 instances to make sure no two performance tests are scheduled on the same instance
    agents={"ag": 1},
    retry=retry,
)

tests = [perf_test[test] for test in pipeline.args.test or perf_test.keys()]
for test in tests:
    devtool_opts = test.pop("devtool_opts")
    test_path = test.pop("test_path")
    ab_opts = test.pop("ab_opts", "")
    devtool_opts += " --performance"
    pytest_opts = ""
    if REVISION_A:
        devtool_opts += " --ab"
        pytest_opts = f"{ab_opts} run {REVISION_A} {REVISION_B} --test {test_path}"
    else:
        # Passing `-m ''` below instructs pytest to collect tests regardless of
        # their markers (e.g. it will collect both tests marked as nonci, and
        # tests without any markers).
        pytest_opts += f" -m '' {test_path}"

    pipeline.build_group(
        command=pipeline.devtool_test(devtool_opts, pytest_opts),
        # and the rest can be command arguments
        **test,
    )


# Stores the info about pinning tests to agents with particular kernel versions.
# For example, the following:
# pins = {
#   "linux_6.1-pinned": {"instance": "m6i.metal", "kv": "linux_6.1"},
# }
# will pin steps running on instances "m6i.metal" with kernel version tagged "linux_6.1"
# to a new kernel version tagged "linux_6.1-pinned"
pins = {
    "linux_5.10-pinned": {"instance": "m6i.metal", "kv": "linux_5.10"},
}


def apply_pins(steps):
    """Apply pins"""
    new_steps = []
    for step in steps:
        if isinstance(step, str):
            pass
        elif "group" in step:
            step["steps"] = apply_pins(step["steps"])
        else:
            agents = step["agents"]
            for new_kv, match in pins.items():
                # if all keys match, apply pin
                if all(agents[k] == v for k, v in match.items()):
                    step["agents"]["kv"] = new_kv
                    break
        new_steps.append(step)
    return new_steps


pipeline.steps = apply_pins(pipeline.steps)
print(pipeline.to_json())
