#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite performance pipelines dynamically"""

import json

from common import group, DEFAULT_INSTANCES, DEFAULT_KERNELS


CMD1 = ["tools/devtool -y test -- -s --nonci integration_tests/functional/test_cpu_features.py -k 'test_cpu_wrmsr_snapshot or test_cpu_cpuid_snapshot'"]
CMD2 = [
    "buildkite-agent artifact download tests/snapshot_artifacts/**/* .",
    "tools/devtool -y test -- -s --nonci integration_tests/functional/test_cpu_features.py -k 'test_cpu_wrmsr_restore or test_cpu_cpuid_restore'"
]


groups = []
# for instance in DEFAULT_INSTANCES:
for instance in ["m5d.metal", "m6i.metal", "m6a.metal"]:
    for kv in ["linux_4.14"]:
        steps = []
        agents = [f"instance={instance}", f"kv={kv}"]
        label = f"{instance} {kv}"
        common = {
            "agents": agents,
            "timeout": 30,
        }
        step1 = {
            "commands": CMD1,
            "label": label + " wrmsr snapshot",
            "artifact_paths": "tests/snapshot_artifacts/**/*",
            **common
        }
        step2 = {
            "commands": CMD2,
            "label": label + " wrmsr restore",
            **common
        }
        steps.append(step1)
        steps.append("wait")
        #steps.append({"wait": ""})
        steps.append(step2)
        groups.append({"group": label, "steps": steps})

pipeline = {
    "agents": {"queue": "public-prod-us-east-1"},
    "steps": groups
}
print(json.dumps(pipeline, indent=4, sort_keys=True, ensure_ascii=False))
