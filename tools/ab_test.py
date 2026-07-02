#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Script for running A/B-Tests

The script takes two git revisions and a pytest integration test. It utilizes
our integration test frameworks --binary-dir parameter to execute the given
test using binaries compiled from each revision, and runs a regression test
comparing resulting metrics between runs.

It performs the A/B-test as follows:
For both A and B runs, collect all `metrics.json` files and read all dimensions
from them. Script assumes all dimensions are unique within single run and both
A and B runs result in the same dimensions. After collection is done, perform
statistical regression test across all the list-valued properties collected.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy
import scipy

UNIT_REDUCTIONS = {
    "Microseconds": "Milliseconds",
    "Milliseconds": "Seconds",
    "Bytes": "Kilobytes",
    "Kilobytes": "Megabytes",
    "Megabytes": "Gigabytes",
    "Gigabytes": "Terabytes",
    "Bits": "Kilobits",
    "Kilobits": "Megabits",
    "Megabits": "Gigabits",
    "Gigabits": "Terabit",
    "Bytes/Second": "Kilobytes/Second",
    "Kilobytes/Second": "Megabytes/Second",
    "Megabytes/Second": "Gigabytes/Second",
    "Gigabytes/Second": "Terabytes/Second",
    "Bits/Second": "Kilobits/Second",
    "Kilobits/Second": "Megabits/Second",
    "Megabits/Second": "Gigabits/Second",
    "Gigabits/Second": "Terabits/Second",
}
INV_UNIT_REDUCTIONS = {v: k for k, v in UNIT_REDUCTIONS.items()}

UNIT_SHORTHANDS = {
    "Seconds": "s",
    "Microseconds": "μs",
    "Milliseconds": "ms",
    "Bytes": "B",
    "Kilobytes": "KB",
    "Megabytes": "MB",
    "Gigabytes": "GB",
    "Terabytes": "TB",
    "Bits": "Bit",
    "Kilobits": "KBit",
    "Megabits": "MBit",
    "Gigabits": "GBit",
    "Terabits": "TBit",
    "Percent": "%",
    "Count": "",
    "Bytes/Second": "B/s",
    "Kilobytes/Second": "KB/s",
    "Megabytes/Second": "MB/s",
    "Gigabytes/Second": "GB/s",
    "Terabytes/Second": "TB/s",
    "Bits/Second": "Bit/s",
    "Kilobits/Second": "KBit/s",
    "Megabits/Second": "MBit/s",
    "Gigabits/Second": "GBit/s",
    "Terabits/Second": "TBit/s",
    "Count/Second": "Hz",
    "None": "",
}


def reduce_value(value, unit):
    """
    Utility function for expressing a value in the largest possible unit in which it would still be >= 1

    For example, `reduce_value(1_000_000, Bytes)` would return (1, Megabytes)
    """
    # Could do this recursively, but I am worried about infinite recursion
    # due to precision problems (e.g. infinite loop of dividing/multiplying by 1000, alternating
    # between values < 1 and >= 1000).
    while abs(value) < 1 and unit in INV_UNIT_REDUCTIONS:
        value *= 1000
        unit = INV_UNIT_REDUCTIONS[unit]
    while abs(value) >= 1000 and unit in UNIT_REDUCTIONS:
        value /= 1000
        unit = UNIT_REDUCTIONS[unit]

    return value, unit


def format_with_reduced_unit(value, unit):
    """
    Utility function for pretty printing a given value by choosing a unit as large as possible,
    and then outputting its shorthand.

    For example, `format_with_reduced_unit(1_000_000, Bytes)` would return "1MB".
    """
    reduced_value, reduced_unit = reduce_value(value, unit)
    formatted_unit = UNIT_SHORTHANDS.get(reduced_unit, reduced_unit)

    return f"{reduced_value:.2f}{formatted_unit}"


# Performance tests that we don't want to alarm on.
IGNORED = [
    # block latencies if guest uses async request submission
    {"fio_engine": "libaio", "metric": "clat_read"},
    {"fio_engine": "libaio", "metric": "clat_write"},
    # boot time metrics
    {"performance_test": "test_boottime", "metric": "resume_time"},
    # memory hotplug metrics: ignore api_time and fc_time metrics, keeping only total_time.
    *[
        {
            "performance_test": "test_memory_hotplug_latency",
            "metric": f"{prefix}_{metric}",
        }
        for prefix in ["hotplug", "hotunplug", "hotplug_2nd"]
        for metric in ["api_time", "fc_time"]
    ],
]


def is_ignored(dimensions) -> bool:
    """Checks whether the given dimensions match an entry in the IGNORED dictionary above"""
    for high_variance in IGNORED:
        matching = {key: dimensions[key] for key in high_variance if key in dimensions}

        if matching == high_variance:
            return True

    return False


def load_data_series(data_path: Path, ignore_dimensions: set[str]):
    """Recursively collects `metrics.json` files in provided path"""
    data = {}
    for name in glob.glob(
        f"{glob.escape(str(data_path))}/**/metrics.json", recursive=True
    ):
        with open(name, encoding="utf-8") as f:
            j = json.load(f)

        metrics = j["metrics"]
        for dim in ignore_dimensions:
            j["dimensions"].pop(dim, None)

        dimensions = frozenset(j["dimensions"].items())

        data[dimensions] = {}
        for m in metrics:
            # Ignore certain metrics as we know them to be volatile
            if "cpu_utilization" in m:
                continue
            mm = metrics[m]
            unit = mm["unit"]
            values = mm["values"]
            data[dimensions][m] = (values, unit)

    return data


def uninteresting_dimensions(data):
    """
    Computes the set of dimensions that only ever take on a
    single value across the entire dataset.
    """
    values_per_dimension = defaultdict(set)

    for dimension_set in data:
        for dimension, value in dimension_set:
            values_per_dimension[dimension].add(value)

    uninteresting = set()

    for dimension, distinct_values in values_per_dimension.items():
        if len(distinct_values) == 1:
            uninteresting.add(dimension)

    return uninteresting


def collect_data(
    tag: str,
    binary_dir: Path,
    artifacts: Optional[Path],
    pytest_opts: str,
    ignore_dimensions: set[str],
    iteration: int = 0,
):
    """
    Executes the specified test using the provided firecracker binaries and
    stores results into the `test_results/tag/iteration` directory
    """
    binary_dir = binary_dir.resolve()

    print(
        f"Collecting samples | binaries path: {binary_dir}"
        + f" | artifacts path: {artifacts}"
        if artifacts
        else ""
    )
    test_path = f"test_results/{tag}/{iteration}"
    test_report_path = f"{test_path}/test-report.json"

    # Cleaning the report directory, to ensure we start from a clean state.
    shutil.rmtree(test_path, ignore_errors=True)

    # It is not possible to just download them here this script is usually run inside docker
    # and artifacts downloading does not work inside it.
    if artifacts:
        subprocess.run(
            f"./tools/devtool set_current_artifacts {artifacts}", check=True, shell=True
        )

    subprocess.run(
        f"./tools/test.sh --binary-dir={binary_dir} {pytest_opts} -m '' --json-report-file=../{test_report_path}",
        env=os.environ,
        check=True,
        shell=True,
    )

    return load_data_series(Path(test_path), ignore_dimensions)


def check_regression(
    a_samples: List[float], b_samples: List[float], *, n_resamples: int = 9999
):
    """Checks for a regression by performing a permutation test. A permutation test is a non-parametric test that takes
    three parameters: Two populations (sets of samples) and a function computing a "statistic" based on two populations.
    First, the test computes the statistic for the initial populations. It then randomly
    permutes the two populations (e.g. merges them and then randomly splits them again). For each such permuted
    population, the statistic is computed. Then, all the statistics are sorted, and the percentile of the statistic for the
    initial populations is computed. We then look at the fraction of statistics that are larger/smaller than that of the
    initial populations. The minimum of these two fractions will then become the p-value.

    The idea is that if the two populations are indeed drawn from the same distribution (e.g. if performance did not
    change), then permuting will not affect the statistic (indeed, it should be approximately normal-distributed, and
    the statistic for the initial populations will be somewhere "in the middle").

    Useful for performance tests.
    """
    return scipy.stats.permutation_test(
        (a_samples, b_samples),
        # Compute the difference of means, such that a positive different indicates potential for regression.
        lambda x, y, axis: numpy.mean(y, axis=axis) - numpy.mean(x, axis=axis),
        n_resamples=n_resamples,
    )


@dataclass
class Threshold:
    """A threshold value with optional per-metric overrides."""

    default: float
    overrides: Dict[str, float] = field(default_factory=dict)

    def get(self, metric: str) -> float:
        """Returns the threshold to use for a specific metric"""
        return self.overrides.get(metric, self.default)

    @classmethod
    def from_args(cls, args, default: float):
        """Parse a list like ["0.05", "restore_latency=0.1"] into a Threshold."""
        overrides = {}
        for arg in args:
            if "=" in arg:
                name, val = arg.rsplit("=", 1)
                overrides[name] = float(val)
            else:
                default = float(arg)
        return cls(default=default, overrides=overrides)


def analyze_data(
    data_a,
    data_b,
    p_thresh: Threshold,
    strength_abs_thresh: Threshold,
    noise_threshold: Threshold,
    *,
    n_resamples: int = 9999,
):
    """
    Analyzes the A/B-test data produced by `collect_data`, by performing regression tests
    as described this script's doc-comment.

    Returns the list of error messages (empty if the test passes).
    """
    assert set(data_a.keys()) == set(
        data_b.keys()
    ), "A and B run produced incomparable data. This is a bug in the test!"

    results = {}

    t0 = time.perf_counter()
    for dimension_set in data_a:
        metrics_a = data_a[dimension_set]
        metrics_b = data_b[dimension_set]

        assert set(metrics_a.keys()) == set(
            metrics_b.keys()
        ), "A and B run produced incomparable data. This is a bug in the test!"

        for metric, (values_a, unit) in metrics_a.items():
            result = check_regression(
                values_a, metrics_b[metric][0], n_resamples=n_resamples
            )
            results[dimension_set, metric] = (result, unit)

    print(f"Regression tests took {time.perf_counter() - t0:.2f}s")

    # Validate that all per-metric overrides refer to metrics that exist in the dataset
    all_metrics = {metric for _, metric in results}
    for thresh in (p_thresh, strength_abs_thresh, noise_threshold):
        unknown = set(thresh.overrides) - all_metrics
        assert not unknown, f"Per-metric overrides refer to unknown metrics: {unknown}"

    # We sort our A/B-Testing results keyed by metric here. The resulting lists of values
    # will be approximately normal distributed, and we will use this property as a means of error correction.
    # The idea behind this is that testing the same metric (say, restore_latency) across different scenarios (e.g.
    # different vcpu counts) will be related in some unknown way (meaning most scenarios will show a change in the same
    # direction). In particular, if one scenario yields a slight improvement and the next yields a
    # slight degradation, we take this as evidence towards both being mere noise that cancels out.
    #
    # Empirical evidence for this assumption is that
    #  1. Historically, a true performance change has never shown up in just a single test, it always showed up
    #     across most (if not all) tests for a specific metric.
    #  2. Analyzing data collected from historical runs shows that across different parameterizations of the same
    #     metric, the collected samples approximately follow mean / variance = const, with the constant independent
    #     of the parameterization.
    #
    # Mathematically, this has the following justification: By the central
    # limit theorem, the means of samples are (approximately) normal distributed. Denote by A
    # and B the distributions of the mean of samples from the 'A' and 'B'
    # tests respectively. Under our null hypothesis, the distributions of the
    # 'A' and 'B' samples are identical (although we dont know what the exact
    # distributions are), meaning so are A and B, say A ~ B ~ N(mu, sigma^2).
    # The difference of two normal distributions is also normal distributed,
    # with the means being subtracted and the variances being added.
    # Therefore, A - B ~ N(0, 2sigma^2). If we now normalize this distribution by mu (which
    # corresponds to considering the distribution of relative regressions instead), we get (A-B)/mu ~ N(0, c), with c
    # being the constant from point 2. above. This means that we can combine the relative means across
    # different parameterizations, and get a distributions whose expected
    # value is 0, provided our null hypothesis was true. It is exactly this distribution
    # for which we collect samples in the dictionary below. Therefore, a sanity check
    # on the average of the average of the performance changes for a single metric
    # is a good candidates for a sanity check against false-positives.
    #
    # Note that with this approach, for performance changes to "cancel out", we would need essentially a perfect split
    # between scenarios that improve performance and scenarios that degrade performance, something we have not
    # ever observed to actually happen.
    relative_changes_by_metric = defaultdict(list)
    relative_changes_significant = defaultdict(list)

    failures = []
    for (dimension_set, metric), (result, unit) in results.items():
        if is_ignored(dict(dimension_set) | {"metric": metric}):
            continue

        print(f"Doing A/B-test for dimensions {dimension_set} and property {metric}")

        values_a = data_a[dimension_set][metric][0]
        baseline_mean = numpy.mean(values_a)

        relative_changes_by_metric[metric].append(result.statistic / baseline_mean)

        if result.pvalue < p_thresh.get(metric) and abs(
            result.statistic
        ) > strength_abs_thresh.get(metric):
            failures.append((dimension_set, metric, result, unit))

            relative_changes_significant[metric].append(
                result.statistic / baseline_mean
            )

    error_messages = []
    do_not_print_list = uninteresting_dimensions(data_a)
    for dimension_set, metric, result, unit in failures:
        # No data points for this metric were deemed significant
        if metric not in relative_changes_significant:
            continue

        relative_change = numpy.mean(relative_changes_by_metric[metric])
        relative_change_significant = numpy.mean(relative_changes_significant[metric])
        # Sanity check as described above
        if abs(relative_change) > noise_threshold.get(metric) and abs(
            relative_change_significant
        ) > noise_threshold.get(metric):
            old_mean = numpy.mean(data_a[dimension_set][metric][0])
            new_mean = numpy.mean(data_b[dimension_set][metric][0])

            msg = (
                f"\033[0;32m[Firecracker A/B-Test Runner]\033[0m A/B-testing shows a change of "
                f"{format_with_reduced_unit(result.statistic, unit)}, or {result.statistic / old_mean:.2%}, "
                f"(from {format_with_reduced_unit(old_mean, unit)} to {format_with_reduced_unit(new_mean, unit)}) "
                f"for metric \033[1m{metric}\033[0m with \033[0;31m\033[1mp={result.pvalue}\033[0m. "
                f"This means that observing a change of this magnitude or worse, assuming that performance "
                f"characteristics did not change across the tested commits, has a probability of {result.pvalue:.2%}. "
                f"Tested Dimensions:\n{json.dumps({k: v for k, v in dimension_set if k not in do_not_print_list}, indent=2, sort_keys=True)}"
            )
            error_messages.append(msg)

    return error_messages


def merge_data(accumulated, new_data):
    """Merge new_data into accumulated by appending values lists for each metric."""
    for dimension_set, metrics in new_data.items():
        if dimension_set not in accumulated:
            accumulated[dimension_set] = {}
        for metric, (values, unit) in metrics.items():
            if metric in accumulated[dimension_set]:
                accumulated[dimension_set][metric][0].extend(values)
            else:
                accumulated[dimension_set][metric] = (list(values), unit)


def ab_performance_test(
    a_directory: Path,
    b_directory: Path,
    a_artifacts: Optional[Path],
    b_artifacts: Optional[Path],
    pytest_opts,
    p_thresh: Threshold,
    strength_abs_thresh: Threshold,
    noise_threshold: Threshold,
    ignore_dimensions: set[str],
    max_iterations=1,
):
    """Does an A/B-test of the specified test with the given firecracker/jailer binaries.

    Retries up to max_iterations times, accumulating data only for dimensions
    that are still failing, to reduce noise-induced false positives."""

    data_a = {}
    data_b = {}
    error_messages = []

    for i in range(max_iterations):
        print(f"\n=== Iteration {i + 1}/{max_iterations} ===")
        # Changing the order or A and B executions across iterations, to avoid fluctuations caused by execution order
        if i % 2 == 0:
            new_a = collect_data(
                "A", a_directory, a_artifacts, pytest_opts, ignore_dimensions, i
            )
            new_b = collect_data(
                "B", b_directory, b_artifacts, pytest_opts, ignore_dimensions, i
            )
        else:
            new_b = collect_data(
                "B", b_directory, b_artifacts, pytest_opts, ignore_dimensions, i
            )
            new_a = collect_data(
                "A", a_directory, a_artifacts, pytest_opts, ignore_dimensions, i
            )
        merge_data(data_a, new_a)
        merge_data(data_b, new_b)

        error_messages = analyze_data(
            data_a,
            data_b,
            p_thresh,
            strength_abs_thresh,
            noise_threshold,
        )

        if not error_messages:
            print("No regressions detected!")
            return

        if i < max_iterations - 1:
            print(
                f"{len(error_messages)} regression(s) detected, retrying to collect more data..."
            )

    assert not error_messages, "\n" + "\n".join(error_messages)


def main():
    """The main function when invoking the script"""
    parser = argparse.ArgumentParser(
        description="Executes Firecracker's A/B testsuite across the specified commits"
    )
    subparsers = parser.add_subparsers(help="commands", dest="command", required=True)
    run_parser = subparsers.add_parser(
        "run",
        help="Run an specific test of our test suite as an A/B-test across two specified commits",
    )
    run_parser.add_argument(
        "--binaries-a",
        help="Directory containing firecracker and jailer binaries to be considered the performance baseline",
        type=Path,
        required=True,
    )
    run_parser.add_argument(
        "--binaries-b",
        help="Directory containing firecracker and jailer binaries whose performance we want to compare against the results from binaries-a",
        type=Path,
        required=True,
    )
    run_parser.add_argument(
        "--artifacts-a",
        help="Name of the artifacts directory in the build/artifacts to use for revision A test. If the directory does not exist, the name will be treated as S3 path and artifacts will be downloaded from there.",
        # Type is string since it can be an s3 path which if passed to `Path` constructor
        # will be incorrectly modified
        type=str,
        required=False,
    )
    run_parser.add_argument(
        "--artifacts-b",
        help="Name of the artifacts directory in the build/artifacts to use for revision B test. If the directory does not exist, the name will be treated as S3 path and artifacts will be downloaded from there.",
        # Type is string since it can be an s3 path which if passed to `Path` constructor
        # will be incorrectly modified
        type=str,
        required=False,
    )
    run_parser.add_argument(
        "--pytest-opts",
        help="Parameters to pass through to pytest, for example for test selection",
        required=True,
    )
    run_parser.add_argument(
        "--max-iterations",
        help="Maximum number of A/B iterations. Retries only if regressions are detected, accumulating more data to reduce false positives.",
        type=int,
        default=1,
    )
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze the results of two manually ran tests based on their metrics.json files",
    )
    analyze_parser.add_argument(
        "path_a",
        help="The path to the directory with run A's metrics.json file",
        type=Path,
    )
    analyze_parser.add_argument(
        "path_b",
        help="The path to the directory with run B's metrics.json file",
        type=Path,
    )
    parser.add_argument(
        "-i",
        "--ignore-dimension",
        help="Dimension key to strip before matching A and B entries. Repeatable.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--significance",
        help="The p-value threshold. Pass a float for the global default, or metric=float for a per-metric override. Repeatable.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--absolute-strength",
        help="The minimum absolute delta. Pass a float for the global default, or metric=float for a per-metric override. Repeatable.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--noise-threshold",
        help="The minimal average relative delta. Pass a float for the global default, or metric=float for a per-metric override. Repeatable.",
        action="append",
        default=[],
    )
    args = parser.parse_args()

    p_thresh = Threshold.from_args(args.significance, 0.01)
    strength_abs_thresh = Threshold.from_args(args.absolute_strength, 0.0)
    noise_threshold = Threshold.from_args(args.noise_threshold, 0.05)

    if args.command == "run":
        t0 = time.perf_counter()
        ab_performance_test(
            args.binaries_a,
            args.binaries_b,
            args.artifacts_a,
            args.artifacts_b,
            args.pytest_opts,
            p_thresh,
            strength_abs_thresh,
            noise_threshold,
            set(args.ignore_dimension),
            max_iterations=args.max_iterations,
        )
        print(f"Total A/B test took {time.perf_counter() - t0:.2f}s")
    else:
        t0 = time.perf_counter()
        data_a = load_data_series(args.path_a, set(args.ignore_dimension))
        data_b = load_data_series(args.path_b, set(args.ignore_dimension))
        print(f"Data loading took {time.perf_counter() - t0:.2f}s")

        t0 = time.perf_counter()
        error_messages = analyze_data(
            data_a,
            data_b,
            p_thresh,
            strength_abs_thresh,
            noise_threshold,
        )
        print(f"Analysis took {time.perf_counter() - t0:.2f}s")
        assert not error_messages, "\n" + "\n".join(error_messages)
        print("No regressions detected!")


if __name__ == "__main__":
    main()
