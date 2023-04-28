#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite performance pipelines dynamically"""

from common import COMMON_PARSER, group, pipeline_to_json

perf_test = {
    "block": {
        "label": "🖴 Block Performance",
        "test_path": "integration_tests/performance/test_block_performance.py",
        "devtool_opts": "-r 16834m -c 1-10 -m 0",
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
        "timeout_in_minutes": 10,
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
    return group(
        label=test.pop("label"),
        command=f"./tools/devtool -y test {devtool_opts} -- --nonci --dump-results-to-file {test_path}",
        agent_tags=["ag=1"],
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
parser.add_argument(
    "--extra",
    required=False,
    action="append",
    default=[],
)
args = parser.parse_args()
if args.extra:
    args.extra = dict(val.split("=", maxsplit=1) for val in args.extra)
group_steps = []
tests = [perf_test[test] for test in args.test]
for test_data in tests:
    test_data.setdefault("platforms", args.platforms)
    test_data.setdefault("instances", args.instances)
    test_data.update(args.extra)
    if args.retries > 0:
        # retry if the step fails
        test_data.setdefault(
            "retry", {"automatic": {"exit_status": 1, "limit": args.retries}}
        )
    group_steps.append(build_group(test_data))

pipeline = {
    "env": {
        "AWS_EMF_SERVICE_NAME": "PerfTests",
        "AWS_EMF_NAMESPACE": "PerfTests",
    },
    "steps": group_steps,
}
print(pipeline_to_json(pipeline))
