# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Optional benchmarks-do-not-regress test"""
import json
import logging
import platform
import shutil
from pathlib import Path

import pytest

from framework import utils
from framework.ab_test import chdir, git_ab_test
from host_tools.cargo_build import cargo

LOGGER = logging.getLogger(__name__)


@pytest.mark.no_block_pr
@pytest.mark.timeout(600)
def test_no_regression_relative_to_target_branch():
    """
    Run the microbenchmarks in this repository, comparing results from pull
    request target branch against what's achieved on HEAD
    """
    git_ab_test(run_criterion, compare_results)


def run_criterion(firecracker_checkout: Path, is_a: bool) -> Path:
    """
    Executes all benchmarks by running "cargo bench --no-run", finding the executables, and running them pinned to some CPU
    """
    baseline_name = "a_baseline" if is_a else "b_baseline"

    with chdir(firecracker_checkout):
        # Passing --message-format json to cargo tells it to print its log in a json format. At the end, instead of the
        # usual "placed executable <...> at <...>" we'll get a json object with an 'executable' key, from which we
        # extract the path to the compiled benchmark binary.
        _, stdout, _ = cargo(
            "bench",
            f"--all --quiet --target {platform.machine()}-unknown-linux-musl --message-format json --no-run",
        )

        executables = []
        for line in stdout.split("\n"):
            if line:
                msg = json.loads(line)
                executable = msg.get("executable")
                if executable:
                    executables.append(executable)

        for executable in executables:
            utils.check_output(
                f"CARGO_TARGET_DIR=build/cargo_target taskset -c 1 {executable} --bench --save-baseline {baseline_name}"
            )

    return firecracker_checkout / "build" / "cargo_target" / "criterion"


def compare_results(location_a_baselines: Path, location_b_baselines: Path):
    """Compares the two recorded criterion baselines for regressions, assuming that "A" is the baseline from main"""
    for benchmark in location_b_baselines.glob("*"):
        data = json.loads(
            (benchmark / "b_baseline" / "estimates.json").read_text("utf-8")
        )

        average_ns = data["mean"]["point_estimate"]

        LOGGER.info("%s mean: %iµs", benchmark.name, average_ns / 1000)

    # Assumption: location_b_baseline = cargo_target of current working directory. So just copy the a_baselines here
    # to do the comparison
    for benchmark in location_a_baselines.glob("*"):
        shutil.copytree(
            benchmark / "a_baseline",
            location_b_baselines / benchmark.name / "a_baseline",
        )

    _, stdout, _ = cargo(
        "bench",
        f"--all --target {platform.machine()}-unknown-linux-musl",
        "--load-baseline a_baseline --baseline b_baseline",
    )

    regressions_only = "\n\n".join(
        result
        for result in stdout.split("\n\n")
        if "Performance has regressed." in result
    )

    # If this string is anywhere in stdout, then at least one of our benchmarks
    # is now performing worse with the PR changes.
    assert not regressions_only, "\n" + regressions_only
