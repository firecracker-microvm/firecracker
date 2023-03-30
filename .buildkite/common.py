# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Common helpers to create Buildkite pipelines
"""

import argparse
import json

DEFAULT_INSTANCES = [
    "m5d.metal",
    "m6i.metal",
    "m6a.metal",
    "m6g.metal",
    "c7g.metal",
]

DEFAULT_PLATFORMS = [
    ("al2", "linux_4.14"),
    ("al2", "linux_5.10"),
    ("al2023", "linux_6.1"),
]


def field_fmt(field, args):
    """If `field` is a string, interpolate variables in `args`"""
    if not isinstance(field, str):
        return field
    return field.format(**args)


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
    commands = command
    if isinstance(command, str):
        commands = [command]
    for instance in instances:
        for os, kv in platforms:
            # fill any templated variables
            args = {"os": os, "kv": kv, "instance": instance}
            step_commands = [cmd.format(**args) for cmd in commands]
            step_kwargs = {key: field_fmt(val, args) for key, val in kwargs.items()}
            agents = [f"instance={instance}", f"kv={kv}", f"os={os}"] + agent_tags
            step = {
                "command": step_commands,
                "label": f"{label1} {instance} {os} {kv}",
                "agents": agents,
                **step_kwargs,
            }
            steps.append(step)

    return {"group": label, "steps": steps}


def pipeline_to_json(pipeline):
    """Serialize a pipeline dictionary to JSON"""
    return json.dumps(pipeline, indent=4, sort_keys=True, ensure_ascii=False)


COMMON_PARSER = argparse.ArgumentParser()
COMMON_PARSER.add_argument(
    "--instances",
    required=False,
    nargs="+",
    default=DEFAULT_INSTANCES,
)
COMMON_PARSER.add_argument(
    "--platforms",
    metavar="OS-KV",
    required=False,
    nargs="+",
    default=DEFAULT_PLATFORMS,
    type=lambda arg: tuple(arg.split("-", maxsplit=1)),
)
COMMON_PARSER.add_argument(
    "--step-param",
    metavar="PARAM=VALUE",
    help="parameters to add to each step",
    required=False,
    action="append",
    default=[],
    type=lambda arg: tuple(arg.split("=", maxsplit=1)),
)
COMMON_PARSER.add_argument(
    "--step-env",
    metavar="KEY=VALUE",
    help="environment to use in each step",
    required=False,
    action="append",
    default=[],
    type=lambda arg: tuple(arg.split("=", maxsplit=1)),
)
