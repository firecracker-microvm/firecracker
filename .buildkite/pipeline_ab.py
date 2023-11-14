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
    run_all_tests,
)

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
        "test_path": "integration_tests/performance/test_memory_overhead.py --noise-threshold 0.01",
        "devtool_opts": "-c 1-10 -m 0",
    },
}

REVISION_A = os.environ["REVISION_A"]
REVISION_B = os.environ["REVISION_B"]


def build_group(test):
    """Build a Buildkite pipeline `group` step"""
    devtool_opts = test.pop("devtool_opts")
    test_path = test.pop("test_path")
    return group(
        label=test.pop("label"),
        command=f"./tools/devtool -y test --performance --ab {devtool_opts} -- {REVISION_A} {REVISION_B} --test {test_path}",
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
    default=list(perf_test.keys()),
    help="performance test",
    action="append",
)

changed_files = get_changed_files(f"{REVISION_A}..{REVISION_B}")
group_steps = []

if run_all_tests(changed_files):
    args = parser.parse_args()
    tests = [perf_test[test] for test in args.test]
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
