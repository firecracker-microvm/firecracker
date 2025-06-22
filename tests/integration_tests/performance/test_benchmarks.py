# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Optional benchmarks-do-not-regress test"""
import contextlib
import logging
import platform
import re
import shutil
from pathlib import Path
from typing import Callable, List

import pytest

from framework import utils
from framework.ab_test import binary_ab_test, git_clone_ab_dirs
from host_tools.cargo_build import cargo

LOGGER = logging.getLogger(__name__)
git_clone_ab_dirs_one_time = pytest.fixture(git_clone_ab_dirs, scope="class")


def get_benchmark_names() -> List[str]:
    """
    Get a list of benchmark test names
    """

    _, stdout, _ = cargo(
        "bench",
        f"--workspace --quiet --target {platform.machine()}-unknown-linux-musl",
        "--list",
    )

    # Format a string like `page_fault #2: benchmark` to a string like `page_fault`.
    benchmark_names = [
        re.sub(r"\s#([0-9]*)", "", i.split(":")[0])
        for i in stdout.split("\n")
        if i.endswith(": benchmark")
    ]

    return list(set(benchmark_names))


class TestBenchMarks:
    """
    This class is used to prevent fixtures from being executed for each parameter in
    a parametrize test.
    """

    @pytest.mark.no_block_pr
    @pytest.mark.timeout(600)
    @pytest.mark.parametrize("benchname", get_benchmark_names())
    def test_no_regression_relative_to_target_branch(
        self, benchname, git_clone_ab_dirs_one_time
    ):
        """
        Run the microbenchmarks in this repository, comparing results from pull
        request target branch against what's achieved on HEAD
        """

        dir_a = git_clone_ab_dirs_one_time[0]
        dir_b = git_clone_ab_dirs_one_time[1]
        run_criterion = get_run_criterion(benchname)
        compare_results = get_compare_results(benchname)

        binary_ab_test(
            test_runner=run_criterion,
            comparator=compare_results,
            a_directory=dir_a,
            b_directory=dir_b,
        )


def get_run_criterion(benchmark_name) -> Callable[[Path, bool], Path]:
    """
    Get function that executes specified benchmarks, and running them pinned to some CPU
    """

    def _run_criterion(firecracker_checkout: Path, is_a: bool) -> Path:
        baseline_name = "a_baseline" if is_a else "b_baseline"

        with contextlib.chdir(firecracker_checkout):
            utils.check_output(
                f"taskset -c 1 cargo bench --workspace --quiet -- {benchmark_name} --exact --save-baseline {baseline_name}"
            )

        return firecracker_checkout / "build" / "cargo_target" / "criterion"

    return _run_criterion


def get_compare_results(benchmark_name) -> Callable[[Path, Path], None]:
    """
    Get function that compares the two recorded criterion baselines for regressions, assuming that "A" is the baseline from main
    """

    def _compare_results(location_a_baselines: Path, location_b_baselines: Path):

        _, stdout, _ = cargo(
            "bench",
            f"--workspace --target {platform.machine()}-unknown-linux-musl --quiet",
            f"--exact {benchmark_name} --list",
        )

        # Format a string like `page_fault #2: benchmark` to a string like `page_fault_2`.
        # Because under `cargo_target/criterion/`, a directory like `page_fault_2` will create.
        bench_mark_targets = [
            re.sub(r"\s#(?P<sub_id>[0-9]*)", r"_\g<sub_id>", i.split(":")[0])
            for i in stdout.split("\n")
            if i.endswith(": benchmark")
        ]

        # If benchmark test has multiple targets, the results of a single benchmark test will be output to multiple directories.
        # For example, `page_fault` and `page_fault_2`.
        # We need copy benchmark results each directories.
        for bench_mark_target in bench_mark_targets:
            shutil.copytree(
                location_a_baselines / bench_mark_target / "a_baseline",
                location_b_baselines / bench_mark_target / "a_baseline",
            )

        _, stdout, _ = cargo(
            "bench",
            f"--workspace --target {platform.machine()}-unknown-linux-musl",
            f"{benchmark_name} --exact --baseline a_baseline --load-baseline b_baseline",
        )

        regressions_only = "\n\n".join(
            result
            for result in stdout.split("\n\n")
            if "Performance has regressed." in result
        )

        # If this string is anywhere in stdout, then at least one of our benchmarks
        # is now performing worse with the PR changes.
        assert not regressions_only, "\n" + regressions_only

    return _compare_results
