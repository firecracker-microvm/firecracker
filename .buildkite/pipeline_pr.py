#!/usr/bin/env python3
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

import subprocess
from pathlib import Path

from common import COMMON_PARSER, group, overlay_dict, pipeline_to_json

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1


def get_changed_files(branch):
    """
    Get all files changed since `branch`
    """
    stdout = subprocess.check_output(["git", "diff", "--name-only", branch])
    return [Path(line) for line in stdout.decode().splitlines()]


args = COMMON_PARSER.parse_args()

step_style = {
    "command": "./tools/devtool -y test -- ../tests/integration_tests/style/",
    "label": "🪶 Style",
    "priority": DEFAULT_PRIORITY,
}

defaults = {
    "instances": args.instances,
    "platforms": args.platforms,
    # buildkite step parameters
    "priority": DEFAULT_PRIORITY,
    "timeout_in_minutes": 45,
    "artifacts": ["./test_results/**/*"],
}
defaults = overlay_dict(defaults, args.step_param)

devtool_build_grp = group(
    "📦 Devtool Sanity Build",
    "./tools/devtool -y build",
    **defaults,
)

build_grp = group(
    "📦 Build",
    "./tools/devtool -y test -- ../tests/integration_tests/build/",
    **defaults,
)

functional_1_grp = group(
    "⚙ Functional [a-n]",
    "./tools/devtool -y test -- `cd tests; ls integration_tests/functional/test_[a-n]*.py`",
    **defaults,
)

functional_2_grp = group(
    "⚙ Functional [o-z]",
    "./tools/devtool -y test -- `cd tests; ls integration_tests/functional/test_[o-z]*.py`",
    **defaults,
)

security_grp = group(
    "🔒 Security",
    "./tools/devtool -y test -- ../tests/integration_tests/security/",
    **defaults,
)

defaults_for_performance = overlay_dict(
    defaults,
    {
        # We specify higher priority so the ag=1 jobs get picked up before the ag=n
        # jobs in ag=1 agents
        "priority": DEFAULT_PRIORITY + 1,
        "agents": {"ag": 1},
    },
)

performance_grp = group(
    "⏱ Performance",
    "./tools/devtool -y test -- ../tests/integration_tests/performance/",
    **defaults_for_performance,
)

defaults_for_kani = overlay_dict(
    defaults_for_performance,
    {
        # Kani runs fastest on m6i.metal
        "instances": ["m6i.metal"],
        "platforms": [("al2", "linux_5.10")],
        "timeout_in_minutes": 300,
    },
)

kani_grp = group(
    "🔍 Kani",
    "./tools/devtool -y test -- ../tests/integration_tests/test_kani.py -n auto",
    **defaults_for_kani,
)
for step in kani_grp["steps"]:
    step["label"] = "🔍 Kani"

steps = [step_style]
changed_files = get_changed_files("main")

# run sanity build of devtool if Dockerfile is changed
if any(x.parts[-1] == "Dockerfile" for x in changed_files):
    steps += [devtool_build_grp]

# run the whole test suite if either of:
# - any file changed that is not documentation nor GitHub action config file
# - no files changed
if not changed_files or any(
    x.suffix != ".md" and not (x.parts[0] == ".github" and x.suffix == ".yml")
    for x in changed_files
):
    steps += [
        kani_grp,
        build_grp,
        functional_1_grp,
        functional_2_grp,
        security_grp,
        performance_grp,
    ]

pipeline = {"steps": steps}
print(pipeline_to_json(pipeline))
