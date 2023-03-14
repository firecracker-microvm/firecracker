#!/usr/bin/env python3
# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

import subprocess
from pathlib import Path

from common import (
    DEFAULT_INSTANCES,
    DEFAULT_INSTANCES_AARCH64,
    DEFAULT_INSTANCES_X86,
    DEFAULT_PLATFORMS,
    DEFAULT_QUEUE,
    group,
    pipeline_to_json,
)

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1


def get_changed_files(branch):
    """
    Get all files changed since `branch`
    """
    stdout = subprocess.check_output(["git", "diff", "--name-only", branch])
    return [Path(line) for line in stdout.decode().splitlines()]


step_style = {
    "command": "./tools/devtool -y test -- ../tests/integration_tests/style/",
    "label": "🪶 Style",
    "priority": DEFAULT_PRIORITY,
}

defaults = {
    "instances": DEFAULT_INSTANCES,
    "platforms": DEFAULT_PLATFORMS,
    # buildkite step parameters
    "priority": DEFAULT_PRIORITY,
    "timeout_in_minutes": 30,
}

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

defaults_for_nonsnap_performance = defaults.copy()
defaults_for_nonsnap_performance.update(
    # We specify higher priority so the ag=1 jobs get picked up before the ag=n
    # jobs in ag=1 agents
    priority=DEFAULT_PRIORITY + 1,
    agent_tags=["ag=1"],
)

performance_nonsnap_grp = group(
    "⏱ Performance (non-snapshot)",
    "./tools/devtool -y test -- ../tests/integration_tests/performance/",
    **defaults_for_nonsnap_performance,
)

defaults_for_snap_performance_aarch64 = defaults_for_nonsnap_performance.copy()
defaults_for_snap_performance_aarch64.update(
    instances=DEFAULT_INSTANCES_AARCH64,
)

performance_snap_aarch64_grp = group(
    "⏱ Performance (snapshot for aarch64)",
    "./tools/devtool -y test -- -m ci_snapshot ../tests/integration_tests/performance/",
    **defaults_for_snap_performance_aarch64,
)

# We have a known issue that snapshot latency is too high on x86 CPUs with cgroups v1.
# https://github.com/firecracker-microvm/firecracker/issues/2027
# To avoid this, only snapshot performance tests need to run with cgroups v2.
defaults_for_snap_performance_x86 = defaults_for_nonsnap_performance.copy()
defaults_for_snap_performance_x86.update(
    instances=DEFAULT_INSTANCES_X86,
    platforms=[("al2", "linux_4.14"), ("al2_cgroupsv2", "linux_5.10")],
)

performance_snap_x86_grp = group(
    "⏱ Performance (snapshot for x86)",
    "./tools/devtool -y test -- -m ci_snapshot ../tests/integration_tests/performance/",
    **defaults_for_snap_performance_x86,
)

steps = [step_style]
changed_files = get_changed_files("main")
if any(x.suffix != ".md" for x in changed_files):
    steps += [
        build_grp,
        functional_1_grp,
        functional_2_grp,
        security_grp,
        performance_nonsnap_grp,
        performance_snap_aarch64_grp,
        performance_snap_x86_grp,
    ]

pipeline = {
    "env": {},
    "agents": {"queue": DEFAULT_QUEUE},
    "steps": steps,
}
print(pipeline_to_json(pipeline))
