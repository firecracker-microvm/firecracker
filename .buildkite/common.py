# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Common helpers to create Buildkite pipelines
"""

DEFAULT_INSTANCES = [
    "m5d.metal",
    "m6i.metal",
    "m6a.metal",
    "m6g.metal",
]

DEFAULT_KERNELS = ["linux_4.14", "linux_5.10"]


def group(label, command, instances, kernels, agent_tags=None, **kwargs):
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
        for kv in kernels:
            agents = [f"instance={instance}", f"kv={kv}"] + agent_tags
            step = {
                "command": command,
                "label": f"{label1} {instance} {kv}",
                "agents": agents,
                **kwargs,
            }
            steps.append(step)

    return {"group": label, "steps": steps}
