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

changed_files = get_changed_files()
DOC_ONLY_CHANGE = False
if changed_files and all(f.suffix == ".md" for f in changed_files):
    DOC_ONLY_CHANGE = True
pipeline = BKPipeline(
    priority=DEFAULT_PRIORITY,
    timeout_in_minutes=45,
    with_build_step=not DOC_ONLY_CHANGE,
)

pipeline.add_step(
    {
        "command": "./tools/devtool -y checkstyle",
        "label": "🪶 Style",
    },
    depends_on_build=False,
)

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

if not pipeline.args.no_kani and (
    not changed_files
    or any(x.suffix in [".rs", ".toml", ".lock"] for x in changed_files)
    or any(x.parent.name == "devctr" for x in changed_files)
):
    kani_grp = pipeline.build_group(
        "🔍 Kani",
        "./tools/devtool -y test --no-build -- ../tests/integration_tests/test_kani.py -n auto",
        # Kani step default
        # Kani runs fastest on m6a.metal
        instances=["m6a.metal", "m7g.metal"],
        platforms=[("al2023", "linux_6.1")],
        timeout_in_minutes=300,
        **DEFAULTS_PERF,
        depends_on_build=False,
    )
    # modify Kani steps' label
    for step in kani_grp["steps"]:
        step["label"] = "🔍 Kani"

if run_all_tests(changed_files):
    pipeline.build_group(
        "📦 Build",
        pipeline.devtool_test(pytest_opts="integration_tests/build/"),
        depends_on_build=False,
    )

    pipeline.build_group(
        "⚙ Functional and security 🔒",
        pipeline.devtool_test(
            pytest_opts="-n 16 --dist worksteal integration_tests/{{functional,security}}",
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
