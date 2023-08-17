# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Common helpers to create Buildkite pipelines
"""

import argparse
import json
import subprocess
from pathlib import Path

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


def overlay_dict(base: dict, update: dict):
    """Overlay a dict over a base one"""
    base = base.copy()
    for key, val in update.items():
        if key in base and isinstance(val, dict):
            base[key] = overlay_dict(base.get(key, {}), val)
        else:
            base[key] = val
    return base


def field_fmt(field, args):
    """If `field` is a string, interpolate variables in `args`"""
    if not isinstance(field, str):
        return field
    return field.format(**args)


def dict_fmt(dict_tmpl, args):
    """Apply field_fmt over a hole dict"""
    res = {}
    for key, val in dict_tmpl.items():
        if isinstance(val, dict):
            res[key] = dict_fmt(val, args)
        else:
            res[key] = field_fmt(val, args)
    return res


def group(label, command, instances, platforms, **kwargs):
    """
    Generate a group step with specified parameters, for each instance+kernel
    combination

    https://buildkite.com/docs/pipelines/group-step
    """
    # Use the 1st character of the group name (should be an emoji)
    label1 = label[0]
    steps = []
    commands = command
    if isinstance(command, str):
        commands = [command]
    for instance in instances:
        for os, kv in platforms:
            # fill any templated variables
            args = {"instance": instance, "os": os, "kv": kv}
            step = {
                "command": [cmd.format(**args) for cmd in commands],
                "label": f"{label1} {instance} {os} {kv}",
                "agents": args,
            }
            step_kwargs = dict_fmt(kwargs, args)
            step = overlay_dict(step_kwargs, step)
            steps.append(step)

    return {"group": label, "steps": steps}


def pipeline_to_json(pipeline):
    """Serialize a pipeline dictionary to JSON"""
    return json.dumps(pipeline, indent=4, sort_keys=True, ensure_ascii=False)


def get_changed_files(branch):
    """
    Get all files changed since `branch`
    """
    stdout = subprocess.check_output(["git", "diff", "--name-only", branch])
    return [Path(line) for line in stdout.decode().splitlines()]


def run_all_tests(changed_files):
    """
    Check if we should run all tests, based on the files that have been changed
    """

    # run the whole test suite if either of:
    # - any file changed that is not documentation nor GitHub action config file
    # - no files changed
    return not changed_files or any(
        x.suffix != ".md" and not (x.parts[0] == ".github" and x.suffix == ".yml")
        for x in changed_files
    )


class DictAction(argparse.Action):
    """An argparse action that can receive a nested dictionary

    Examples:

        --step-param a/b/c=3
        {"a": {"b": {"c": 3}}}
    """

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        res = getattr(namespace, self.dest, {})
        key_str, val = value.split("=", maxsplit=1)
        keys = key_str.split("/")
        update = {keys[-1]: val}
        for key in list(reversed(keys))[1:]:
            update = {key: update}
        res = overlay_dict(res, update)
        setattr(namespace, self.dest, res)


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
    action=DictAction,
    default={},
    type=str,
)
