# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Common helpers to create Buildkite pipelines
"""

import json

DEFAULT_INSTANCES = [
    "m5d.metal",
    "m6i.metal",
    "m6a.metal",
    "m6g.metal",
]

DEFAULT_PLATFORMS = [("al2", "linux_4.14"), ("al2", "linux_5.10")]

DEFAULT_QUEUE = "public-prod-us-east-1"


def group(label, command, instances, platforms, agent_tags=None, **kwargs):
    """
    Generate a group step with specified parameters, for each instance+kernel
    combination

    https://buildkite.com/docs/pipelines/group-step
    """
    if agent_tags is None:
        agent_tags = []
    # Use the 1st character of the group name (should be an emoji)
    label1 = label[0]
    steps = []
    for instance in instances:
        for (os, kv) in platforms:
            agents = [f"instance={instance}", f"kv={kv}", f"os={os}"] + agent_tags
            step = {
                "command": command,
                "label": f"{label1} {instance} {os} {kv}",
                "agents": agents,
                **kwargs,
            }
            steps.append(step)

    return {"group": label, "steps": steps}


def pipeline_to_json(pipeline):
    """Serialize a pipeline dictionary to JSON"""
    return json.dumps(pipeline, indent=4, sort_keys=True, ensure_ascii=False)
