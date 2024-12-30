# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Optional benchmarks-do-not-regress test"""
import contextlib
import json
import logging
import platform
import re
import shutil
from pathlib import Path

import pytest

from framework import utils
from framework.ab_test import git_ab_test
from host_tools.cargo_build import cargo

LOGGER = logging.getLogger(__name__)


def get_executables():
    """
    Get a list of binaries for benchmarking
    """

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

    return executables


@pytest.mark.no_block_pr
@pytest.mark.timeout(600)
@pytest.mark.parametrize("executable", get_executables())
def test_no_regression_relative_to_target_branch(executable):
    """
    Run the microbenchmarks in this repository, comparing results from pull
    request target branch against what's achieved on HEAD
    """
    run_criterion = get_run_criterion(executable)
    compare_results = get_compare_results(executable)
    git_ab_test(run_criterion, compare_results)


def get_run_criterion(executable):
    """
    Get function that executes specified benchmarks, and running them pinned to some CPU
    """

    def _run_criterion(firecracker_checkout: Path, is_a: bool) -> Path:
        baseline_name = "a_baseline" if is_a else "b_baseline"

        with contextlib.chdir(firecracker_checkout):
            utils.check_output(
                f"CARGO_TARGET_DIR=build/cargo_target taskset -c 1 {executable} --bench --save-baseline {baseline_name}"
            )

        return firecracker_checkout / "build" / "cargo_target" / "criterion"

    return _run_criterion


def get_compare_results(executable):
    """
    Get function that compares the two recorded criterion baselines for regressions, assuming that "A" is the baseline from main
    """

    def _compare_results(location_a_baselines: Path, location_b_baselines: Path):

        list_result = utils.check_output(
            f"CARGO_TARGET_DIR=build/cargo_target {executable} --bench --list"
        )

        # Format a string like `page_fault #2: benchmark` to a string like `page_fault_2`.
        # Because under `cargo_target/criterion/`, a directory like `page_fault_2` will create.
        bench_marks = [
            re.sub(r"\s#(?P<sub_id>[1-9]+)", r"_\g<sub_id>", i.split(":")[0])
            for i in list_result.stdout.split("\n")
            if i.endswith(": benchmark")
        ]

        for benchmark in bench_marks:
            data = json.loads(
                (
                    location_b_baselines / benchmark / "b_baseline" / "estimates.json"
                ).read_text("utf-8")
            )

            average_ns = data["mean"]["point_estimate"]

            LOGGER.info("%s mean: %iµs", benchmark, average_ns / 1000)

        # Assumption: location_b_baseline = cargo_target of current working directory. So just copy the a_baselines here
        # to do the comparison

        for benchmark in bench_marks:
            shutil.copytree(
                location_a_baselines / benchmark / "a_baseline",
                location_b_baselines / benchmark / "a_baseline",
            )

        bench_result = utils.check_output(
            f"CARGO_TARGET_DIR=build/cargo_target {executable} --bench --baseline a_baseline --load-baseline b_baseline",
            True,
            Path.cwd().parent,
        )

        regressions_only = "\n\n".join(
            result
            for result in bench_result.stdout.split("\n\n")
            if "Performance has regressed." in result
        )

        # If this string is anywhere in stdout, then at least one of our benchmarks
        # is now performing worse with the PR changes.
        assert not regressions_only, "\n" + regressions_only

    return _compare_results
