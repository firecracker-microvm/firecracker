#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite performance pipelines dynamically"""
import os

from common import (
    COMMON_PARSER,
    get_changed_files,
    group,
    overlay_dict,
    pipeline_to_json,
)

# In `devtool_opts`, we restrict both the set of CPUs on which the docker container's threads can run,
# and its memory node. For the cpuset, we pick a continuous set of CPUs from a single NUMA node
# that is large enough so that every firecracker thread can get its own core. We exclude core #0, as
# the operating system sometimes uses it for book-keeping tasks. The memory node (-m parameter)
# has to be the node associated with the NUMA node from which we picked CPUs.
perf_test = {
    "virtio-block": {
        "label": "🖴 Virtio Block Performance",
        "test_path": "integration_tests/performance/test_block_ab.py::test_block_performance",
        "devtool_opts": "-c 1-10 -m 0",
    },
    "vhost-user-block": {
        "label": "🖴 vhost-user Block Performance",
        "test_path": "integration_tests/performance/test_block_ab.py::test_block_vhost_user_performance",
        "devtool_opts": "-c 1-10 -m 0",
        "ab_opts": "--noise-threshold 0.1",
    },
    "network-latency": {
        "label": "🖧 Network Latency",
        "test_path": "integration_tests/performance/test_network_ab.py::test_network_latency",
        "devtool_opts": "-c 1-10 -m 0",
    },
    "network-throughput": {
        "label": "🖧 Network TCP Throughput",
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
        "label": "💾 Memory Overhead",
        "test_path": "integration_tests/performance/test_memory_overhead.py",
        "devtool_opts": "-c 1-10 -m 0",
        "ab_opts": "--noise-threshold 0.01",
    },
}

REVISION_A = os.environ.get("REVISION_A")
REVISION_B = os.environ.get("REVISION_B")

# Either both are specified or neither. Only doing either is a bug. If you want to
# run performance tests _on_ a specific commit, specify neither and put your commit
# into buildkite's "commit" field.
assert (REVISION_A and REVISION_B) or (not REVISION_A and not REVISION_B)


def build_group(test):
    """Build a Buildkite pipeline `group` step"""
    devtool_opts = test.pop("devtool_opts")
    test_path = test.pop("test_path")
    ab_opts = test.pop("ab_opts", "")
    if REVISION_A:
        command = f"./tools/devtool -y test --performance --ab {devtool_opts} -- {REVISION_A} {REVISION_B} --test {test_path} {ab_opts}"
    else:
        command = f"./tools/devtool -y test --performance {devtool_opts} -- -m nonci {test_path}"
    return group(
        label=test.pop("label"),
        command=command,
        artifacts=["./test_results/*"],
        instances=test.pop("instances"),
        platforms=test.pop("platforms"),
        # and the rest can be command arguments
        **test,
    )


parser = COMMON_PARSER
parser.add_argument(
    "--test",
    choices=list(perf_test.keys()),
    required=False,
    help="performance test",
    action="append",
)

RUN_TESTS = True
if REVISION_A is not None:
    changed_files = get_changed_files(f"{REVISION_A}..{REVISION_B}")
    # Our A/B-Testing setup by design only A/B-tests firecracker binaries.
    # So we only trigger A/B-tests on file changes that have impact on the firecracker
    # binary. These include ".rs" files, "Cargo.toml" and "Cargo.lock" files, as well
    # as ".cargo/config".
    RUN_TESTS = any(
        x.suffix in [".rs", ".toml", ".lock", "config"] for x in changed_files
    )

group_steps = []

if RUN_TESTS:
    args = parser.parse_args()
    tests = [perf_test[test] for test in args.test or perf_test.keys()]
    for test_data in tests:
        test_data.setdefault("platforms", args.platforms)
        test_data.setdefault("instances", args.instances)
        # use ag=1 instances to make sure no two performance tests are scheduled on the same instance
        test_data.setdefault("agents", {"ag": 1})
        test_data = overlay_dict(test_data, args.step_param)
        test_data["retry"] = {
            "automatic": [
                # Agent was lost, retry one time
                # this can happen if we terminate the instance or the agent gets
                # disconnected for whatever reason
                {"exit_status": -1, "limit": 1},
            ]
        }
        group_steps.append(build_group(test_data))

pipeline = {
    "env": {},
    "steps": group_steps,
}
print(pipeline_to_json(pipeline))
