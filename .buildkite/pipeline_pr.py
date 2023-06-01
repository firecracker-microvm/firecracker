#!/usr/bin/env python3
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

from common import (
    COMMON_PARSER,
    get_changed_files,
    group,
    overlay_dict,
    pipeline_to_json,
    run_all_tests,
)

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1


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

functional_grp = group(
    "⚙ Functional and security 🔒",
    "./tools/devtool -y test -- -n 8 --dist worksteal integration_tests/{{functional,security}}",
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

if run_all_tests(changed_files):
    steps += [
        kani_grp,
        build_grp,
        functional_grp,
        performance_grp,
    ]

pipeline = {"steps": steps}
print(pipeline_to_json(pipeline))
