# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Common helpers to create Buildkite pipelines
"""

import argparse
import json
import os
import random
import string
import subprocess
from pathlib import Path

DEFAULT_INSTANCES = [
    "c5n.metal",  # Intel Skylake
    "m5n.metal",  # Intel Cascade Lake
    "m6i.metal",  # Intel Icelake
    "m6a.metal",  # AMD Milan
    "m6g.metal",  # Graviton2
    "m7g.metal",  # Graviton3
]

DEFAULT_PLATFORMS = [
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
        for os_, kv in platforms:
            # fill any templated variables
            args = {"instance": instance, "os": os_, "kv": kv}
            step = {
                "command": [cmd.format(**args) for cmd in commands],
                "label": f"{label1} {instance} {os_} {kv}",
                "agents": args,
            }
            step_kwargs = dict_fmt(kwargs, args)
            step = overlay_dict(step_kwargs, step)
            steps.append(step)

    return {"group": label, "steps": steps}


def get_changed_files():
    """
    Get all files changed since `branch`
    """
    # Files are changed only in context of a PR
    if os.environ.get("BUILDKITE_PULL_REQUEST", "false") == "false":
        return []

    branch = os.environ.get("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "main")

    stdout = subprocess.check_output(f"git diff --name-only origin/{branch}".split(" "))

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
COMMON_PARSER.add_argument(
    "--binary-dir",
    help="Use the Firecracker binaries from this path",
    required=False,
    default=None,
    type=str,
)


def random_str(k: int):
    """Generate a random string of hex characters."""
    return "".join(random.choices(string.hexdigits, k=k))


def ab_revision_build(revision):
    """Generate steps for building an A/B-test revision"""
    # Copied from framework/ab_test. Double dollar signs needed for Buildkite (otherwise it will try to interpolate itself)
    return [
        f"commitish={revision}",
        f"if ! git cat-file -t $$commitish; then commitish=origin/{revision}; fi",
        "branch_name=tmp-$$commitish",
        "git branch $$branch_name $$commitish",
        f"git clone -b $$branch_name . build/{revision}",
        f"cd build/{revision} && ./tools/devtool -y build --release && cd -",
        "git branch -D $$branch_name",
    ]


def shared_build():
    """Helper function to make it simple to share a compilation artifacts for a
    whole Buildkite build
    """

    # We need to support 3 scenarios here:
    # 1. We are running in the nightly pipeline - only compile the HEAD of main.
    # 2. We are running in a PR pipeline - compile HEAD of main as revision A and HEAD of PR branch as revision B.
    # 3. We are running in an A/B-test pipeline - compile what is passed via REVISION_{A,B} environment variables.
    rev_a = os.environ.get("REVISION_A")
    if rev_a is not None:
        rev_b = os.environ.get("REVISION_B")
        assert rev_b is not None, "REVISION_B environment variable not set"
        build_cmds = ab_revision_build(rev_a)
        if rev_a != rev_b:
            build_cmds += ab_revision_build(rev_b)
    elif os.environ.get("BUILDKITE_PULL_REQUEST", "false") != "false":
        build_cmds = ab_revision_build(
            os.environ.get("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "main")
        ) + ["./tools/devtool -y build --release"]
    else:
        build_cmds = ["./tools/devtool -y build --release"]
    binary_dir = f"build_$(uname -m)_{random_str(k=8)}.tar.gz"
    build_cmds += [
        "du -sh build/*",
        f"tar czf {binary_dir} build",
        f"buildkite-agent artifact upload {binary_dir}",
    ]
    return build_cmds, binary_dir


class BKPipeline:
    """
    Buildkite Pipeline class abstraction

    Helper class to easily construct pipelines.
    """

    parser = COMMON_PARSER

    def __init__(self, initial_steps=None, with_build_step=True, **kwargs):
        self.steps = []
        self.args = args = self.parser.parse_args()
        # Retry one time if agent was lost. This can happen if we terminate the
        # instance or the agent gets disconnected for whatever reason
        retry = {
            "automatic": [{"exit_status": -1, "limit": 1}],
        }
        retry = overlay_dict(retry, kwargs.pop("retry", {}))
        # Calculate step defaults with parameters and kwargs
        per_instance = {
            "instances": args.instances,
            "platforms": args.platforms,
            "artifact_paths": ["./test_results/**/*"],
            "retry": retry,
            **kwargs,
        }
        self.per_instance = overlay_dict(per_instance, args.step_param)
        self.per_arch = self.per_instance.copy()
        self.per_arch["instances"] = ["m6i.metal", "m7g.metal"]
        self.per_arch["platforms"] = [("al2", "linux_5.10")]
        self.binary_dir = args.binary_dir
        # Build sharing
        if with_build_step:
            build_cmds, self.shared_build = shared_build()
            step_build = group("🏗️ Build", build_cmds, **self.per_arch)
            self.steps += [step_build, "wait"]
        else:
            self.shared_build = None

        # If we run initial_steps before the "wait" step above, then a failure of the initial steps
        # would result in the build not progressing past the "wait" step (as buildkite only proceeds past a wait step
        # if everything before it passed). Thus put the initial steps after the "wait" step, but set `"depends_on": null`
        # to start running them immediately (e.g. without waiting for the "wait" step to unblock).
        #
        # See also https://buildkite.com/docs/pipelines/dependencies#explicit-dependencies-in-uploaded-steps
        if initial_steps:
            for step in initial_steps:
                step["depends_on"] = None

            self.steps += initial_steps

    def add_step(self, step, decorate=True):
        """
        Add a step to the pipeline.

        https://buildkite.com/docs/pipelines/step-reference

        :param step: a Buildkite step
        :param decorate: inject needed commands for sharing builds
        """
        if decorate and isinstance(step, dict):
            step = self._adapt_group(step)
        self.steps.append(step)
        return step

    def _adapt_group(self, group):
        """"""
        prepend = []
        if self.shared_build is not None:
            prepend = [
                f'buildkite-agent artifact download "{self.shared_build}" .',
                f"tar xzf {self.shared_build}",
            ]
        if self.binary_dir is not None:
            prepend.extend(
                [
                    f'buildkite-agent artifact download "{self.binary_dir}/$(uname -m)/*" .',
                    f"chmod -v a+x {self.binary_dir}/**/*",
                ]
            )

        for step in group["steps"]:
            step["command"] = prepend + step["command"]
        return group

    def build_group(self, *args, **kwargs):
        """
        Build a group, parametrizing over the selected instances/platforms.

        https://buildkite.com/docs/pipelines/group-step
        """
        combined = overlay_dict(self.per_instance, kwargs)
        return self.add_step(group(*args, **combined))

    def build_group_per_arch(self, *args, **kwargs):
        """
        Build a group, parametrizing over the architectures only.
        """
        combined = overlay_dict(self.per_arch, kwargs)
        return self.add_step(group(*args, **combined))

    def to_dict(self):
        """Render the pipeline as a dictionary."""
        return {"steps": self.steps}

    def to_json(self):
        """Serialize the pipeline to JSON"""
        return json.dumps(self.to_dict(), indent=4, sort_keys=True, ensure_ascii=False)

    def devtool_test(self, devtool_opts=None, pytest_opts=None):
        """Generate a `devtool test` command"""
        cmds = []
        parts = ["./tools/devtool -y test"]
        if self.shared_build is not None:
            parts.append("--no-build")
        if devtool_opts:
            parts.append(devtool_opts)
        parts.append("--")
        if self.binary_dir is not None:
            parts.append(f"--binary-dir=../{self.binary_dir}/$(uname -m)")
        if pytest_opts:
            parts.append(pytest_opts)
        cmds.append(" ".join(parts))
        return cmds
