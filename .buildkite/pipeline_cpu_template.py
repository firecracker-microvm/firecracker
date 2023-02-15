#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite CPU template pipelines dynamically"""

import argparse
import json

from common import group, DEFAULT_INSTANCES, DEFAULT_KERNELS

cpu_template_test = {
    "rdmsr": [
        {
            "label": "🖴 rdmsr",
            "test_path": "integration_tests/functional/test_cpu_features.py::test_cpu_rdmsr",
            "devtool_opts": " ",
            "instances": ["m5d.metal", "m6i.metal", "m6a.metal"],
        },
    ],
}


def build_group(test):
    """Build a Buildkite pipeline `group` step"""
    devtool_opts = test.pop("devtool_opts")
    test_path = test.pop("test_path")
    return group(
        label=test.pop("label"),
        command=f"./tools/devtool -y test {devtool_opts} -- --nonci -s --dump-results-to-file --log-cli-level=INFO {test_path}",
        instances=test.pop("instances"),
        kernels=test.pop("kernels"),
        # and the rest can be command arguments
        **test
    )


parser = argparse.ArgumentParser()
parser.add_argument(
    "--test",
    required=True,
    choices=list(cpu_template_test.keys()),
    help="CPU template test"
)
parser.add_argument(
    "--add-instance",
    required=False,
    action="append",
    default=DEFAULT_INSTANCES,
)
args = parser.parse_args()
if not args.add_instance:
    args.add_instance = DEFAULT_INSTANCES
group_steps = []
tests = cpu_template_test[args.test]
if isinstance(tests, dict):
    tests = [tests]
for test_data in tests:
    test_data.setdefault("kernels", DEFAULT_KERNELS)
    test_data.setdefault("instances", args.add_instance)
    group_steps.append(build_group(test_data))


pipeline = {
    "env": {
        "AWS_EMF_SERVICE_NAME": "CPUTemplateTests",
        "AWS_EMF_NAMESPACE": "CPUTemplateTests",
    },
    "agents": {"queue": "public-prod-us-east-1"},
    "steps": group_steps
}
print(json.dumps(pipeline, indent=4, sort_keys=True, ensure_ascii=False))
