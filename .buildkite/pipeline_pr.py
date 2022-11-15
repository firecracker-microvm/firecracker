#!/usr/bin/env python3
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

import json

INSTANCES = [
    "m5d.metal",
    "m6i.metal",
    "m6a.metal",
    "m6gd.metal",
]

KERNELS = ["4.14", "5.10"]


def group(group_name, command, agent_tags=None, priority=0, timeout=30):
    """
    Generate a group step with specified parameters, for each instance+kernel
    combination

    https://buildkite.com/docs/pipelines/group-step
    """
    if agent_tags is None:
        agent_tags = []
    # Use the 1st character of the group name (should be an emoji)
    label1 = group_name[0]
    steps = []
    for instance in INSTANCES:
        for kv in KERNELS:
            agents = [
                f"type={instance}",
                f"kv={kv}",
            ]
            agents.extend(agent_tags)
            step = {
                "command": command,
                "label": f"{label1} {instance} kv={kv}",
                "priority": priority,
                "timeout": timeout,
                "agents": agents,
            }
            steps.append(step)

    return {"group": group_name, "steps": steps}


step_block_unless_maintainer = {
    "block": "Waiting for approval to run",
    "if": '(build.creator.teams includes "prod-compute-capsule") == false',
}

step_style = {
    "command": "./tools/devtool -y test -- ../tests/integration_tests/style/",
    "label": "🪶 Style",
    # we only install the required dependencies in x86_64
    "agents": ["platform=x86_64.metal"]
}

build_grp = group(
    "📦 Build",
    "./tools/devtool -y test -- ../tests/integration_tests/build/",
    priority=1,
)

functional_1_grp = group(
    "⚙ Functional [a-n]",
    "./tools/devtool -y test -- `cd tests; ls integration_tests/functional/test_[a-n]*.py`",
    priority=1,
)

functional_2_grp = group(
    "⚙ Functional [o-z]",
    "./tools/devtool -y test -- `cd tests; ls integration_tests/functional/test_[o-z]*.py`",
    priority=1,
)

security_grp = group(
    "🔒 Security",
    "./tools/devtool -y test -- ../tests/integration_tests/security/",
    priority=1,
)

performance_grp = group(
    "⏱ Performance",
    "./tools/devtool -y test -- ../tests/integration_tests/performance/",
    priority=1,
    agent_tags=["ag=1"],
)

pipeline = {
    "agents": {"queue": "default"},
    "steps": [
        step_block_unless_maintainer,
        step_style,
        build_grp,
        functional_1_grp,
        functional_2_grp,
        security_grp,
        performance_grp,
    ],
}

print(json.dumps(pipeline, indent=4, sort_keys=True, ensure_ascii=False))
