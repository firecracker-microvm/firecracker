#!/usr/bin/env python3
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

from common import BKPipeline, get_changed_files, run_all_tests

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1
DEFAULTS_PERF = {
    "priority": DEFAULT_PRIORITY + 1,
    "agents": {"ag": 1},
}

pipeline = BKPipeline(
    priority=DEFAULT_PRIORITY,
    timeout_in_minutes=45,
    initial_steps=[
        {
            "command": "./tools/devtool -y checkstyle",
            "label": "🪶 Style",
        },
    ],
)

changed_files = get_changed_files()

# run sanity build of devtool if Dockerfile is changed
if any(x.parent.name == "devctr" for x in changed_files):
    pipeline.build_group_per_arch(
        "🐋 Dev Container Sanity Build",
        "./tools/devtool -y build_devctr && DEVCTR_IMAGE_TAG=latest ./tools/devtool test -- integration_tests/functional/test_api.py",
    )

if any(
    x.parent.name == "tools" and ("release" in x.name or x.name == "devtool")
    for x in changed_files
):
    pipeline.build_group_per_arch(
        "📦 Release Sanity Build",
        "./tools/devtool -y make_release",
    )

if not changed_files or any(
    x.suffix in [".rs", ".toml", ".lock"] for x in changed_files
):
    kani_grp = pipeline.build_group(
        "🔍 Kani",
        "./tools/devtool -y test -- ../tests/integration_tests/test_kani.py -n auto",
        # Kani step default
        # Kani runs fastest on m6a.metal
        instances=["m6a.metal"],
        platforms=[("al2", "linux_5.10")],
        timeout_in_minutes=300,
        **DEFAULTS_PERF,
    )
    # modify Kani steps' label
    for step in kani_grp["steps"]:
        step["label"] = "🔍 Kani"

if run_all_tests(changed_files):
    pipeline.build_group(
        "📦 Build",
        pipeline.devtool_test(pytest_opts="integration_tests/build/"),
    )

    pipeline.build_group(
        "⚙ Functional and security 🔒",
        pipeline.devtool_test(
            pytest_opts="-n 8 --dist worksteal integration_tests/{{functional,security}}",
        ),
    )

    pipeline.build_group(
        "⏱ Performance",
        pipeline.devtool_test(
            devtool_opts="--performance -c 1-10 -m 0",
            pytest_opts="../tests/integration_tests/performance/",
        ),
        **DEFAULTS_PERF,
    )

print(pipeline.to_json())
