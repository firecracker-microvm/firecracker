#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite performance pipelines dynamically"""

from common import COMMON_PARSER, group, overlay_dict, pipeline_to_json

# In `devtool_opts`, we restrict both the set of CPUs on which the docker container's threads can run,
# and its memory node. For the cpuset, we pick a continuous set of CPUs from a single NUMA node
# that is large enough so that every firecracker thread can get its own core. We exclude core #0, as
# the operating system sometimes uses it for book-keeping tasks. The memory node (-m parameter)
# has to be the node associated with the NUMA node from which we picked CPUs.
perf_test = {
    "virtio-block": {
        "label": "🖴 Virtio Block Performance",
        "test_path": "integration_tests/performance/test_block_performance.py::test_block_performance",
        "devtool_opts": "-c 1-10 -m 0",
        "timeout_in_minutes": 240,
    },
    "vhost-user-block": {
        "label": "🖴 Vhost-user Block Performance",
        "test_path": "integration_tests/performance/test_block_performance.py::test_block_vhost_user_performance",
        "devtool_opts": "-c 1-10 -m 0",
        "timeout_in_minutes": 240,
    },
    "snapshot-latency": {
        "label": "📸 Snapshot Latency",
        "test_path": "integration_tests/performance/test_snapshot_restore_performance.py",
        "devtool_opts": "-c 1-12 -m 0",
        "timeout_in_minutes": 60,
    },
    "vsock-throughput": {
        "label": "🧦 Vsock Throughput",
        "test_path": "integration_tests/performance/test_vsock_throughput.py",
        "devtool_opts": "-c 1-10 -m 0",
        "timeout_in_minutes": 20,
    },
    "network-latency": {
        "label": "🖧 Network Latency",
        "test_path": "integration_tests/performance/test_network_latency.py",
        "devtool_opts": "-c 1-10 -m 0",
    },
    "network-throughput": {
        "label": "🖧 Network TCP Throughput",
        "test_path": "integration_tests/performance/test_network_tcp_throughput.py",
        "devtool_opts": "-c 1-10 -m 0",
        "timeout_in_minutes": 45,
    },
}


def build_group(test):
    """Build a Buildkite pipeline `group` step"""
    devtool_opts = test.pop("devtool_opts")
    test_path = test.pop("test_path")
    retries = test.pop("retries")
    return group(
        label=test.pop("label"),
        command=f"./tools/devtool -y test --performance {devtool_opts} -- -m nonci --reruns {retries} --perf-fail {test_path}",
        artifacts=["./test_results/*"],
        instances=test.pop("instances"),
        platforms=test.pop("platforms"),
        # and the rest can be command arguments
        **test,
    )


parser = COMMON_PARSER
parser.add_argument(
    "--test",
    required=True,
    choices=list(perf_test.keys()),
    help="performance test",
    action="append",
)
parser.add_argument("--retries", type=int, default=0)
args = parser.parse_args()
group_steps = []
tests = [perf_test[test] for test in args.test]
for test_data in tests:
    test_data.setdefault("platforms", args.platforms)
    test_data.setdefault("instances", args.instances)
    # use ag=1 instances to make sure no two performance tests are scheduled on the same instance
    test_data.setdefault("agents", {"ag": 1})
    test_data["retries"] = args.retries
    if "timeout_in_minutes" in test_data:
        test_data["timeout_in_minutes"] *= args.retries + 1
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
