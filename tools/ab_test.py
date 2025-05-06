#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Script for running A/B-Tests

The script takes two git revisions and a pytest integration test. It utilizes
our integration test frameworks --binary-dir parameter to execute the given
test using binaries compiled from each revision, and captures the EMF logs
output. It the searches for list-valued properties/metrics in the EMF, and runs a
regression test comparing these lists for the two runs.

It performs the A/B-test as follows:
For each EMF log message output, look at the dimensions. The script assumes that
dimensions are unique across all log messages output from a single test run. In
each log message, then look for all properties that have lists assigned to them,
and collect them. For both runs of the test, the set of distinct dimensions
collected this way must be the same. Then, we match corresponding dimensions
between the two runs, performing statistical regression test across all the list-
valued properties collected.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Hack to be able to use our test framework code
sys.path.append(str(Path(__file__).parent.parent / "tests"))

# pylint:disable=wrong-import-position
from framework.ab_test import binary_ab_test, check_regression
from framework.properties import global_props
from host_tools.metrics import (
    emit_raw_emf,
    format_with_reduced_unit,
    get_metrics_logger,
)

# Performance tests that are known to be unstable and exhibit variances of up to 60% of the mean
IGNORED = [
    # Network throughput on m6a.metal
    {"instance": "m6a.metal", "performance_test": "test_network_tcp_throughput"},
    # Network throughput on m7a.metal
    {"instance": "m7a.metal-48xl", "performance_test": "test_network_tcp_throughput"},
    # block latencies if guest uses async request submission
    {"fio_engine": "libaio", "metric": "clat_read"},
    {"fio_engine": "libaio", "metric": "clat_write"},
    # boot time metrics
    {"performance_test": "test_boottime", "metric": "resume_time"},
    # block throughput on m8g
    {"fio_engine": "libaio", "vcpus": 2, "instance": "m8g.metal-24xl"},
    {"fio_engine": "libaio", "vcpus": 2, "instance": "m8g.metal-48xl"},
]


def is_ignored(dimensions) -> bool:
    """Checks whether the given dimensions match an entry in the IGNORED dictionary above"""
    for high_variance in IGNORED:
        matching = {key: dimensions[key] for key in high_variance if key in dimensions}

        if matching == high_variance:
            return True

    return False


def extract_dimensions(emf):
    """Extracts the cloudwatch dimensions from an EMF log message"""
    if not emf["_aws"]["CloudWatchMetrics"][0]["Dimensions"]:
        # Skipped tests emit a duration metric, but have no dimensions set
        return {}

    dimension_list = [
        dim
        for dimensions in emf["_aws"]["CloudWatchMetrics"][0]["Dimensions"]
        for dim in dimensions
    ]
    return {key: emf[key] for key in emf if key in dimension_list}


def process_log_entry(emf: dict):
    """Parses the given EMF log entry

    Returns the entries dimensions and its list-valued properties/metrics, together with their units
    """
    result = {
        key: (value, find_unit(emf, key))
        for key, value in emf.items()
        if (
            "fc_metrics" not in key
            and "cpu_utilization" not in key
            and isinstance(value, list)
        )
    }
    # Since we don't consider metrics having fc_metrics in key
    # result could be empty so, return empty dimensions as well
    if not result:
        return {}, {}

    return extract_dimensions(emf), result


def find_unit(emf: dict, metric: str):
    """Determines the unit of the given metric"""
    metrics = {
        y["Name"]: y["Unit"] for y in emf["_aws"]["CloudWatchMetrics"][0]["Metrics"]
    }
    return metrics.get(metric, "None")


def load_data_series(report_path: Path, tag=None, *, reemit: bool = False):
    """Loads the data series relevant for A/B-testing from test_results/test-report.json
    into a dictionary mapping each message's cloudwatch dimensions to a dictionary of
    its list-valued properties/metrics.

    If `reemit` is True, it also reemits all EMF logs to a local EMF agent,
    overwriting the attached "git_commit_id" field with the given revision."""
    # Dictionary mapping EMF dimensions to A/B-testable metrics/properties
    processed_emf = {}

    report = json.loads(report_path.read_text("UTF-8"))
    for test in report["tests"]:
        for line in test["teardown"]["stdout"].splitlines():
            # Only look at EMF log messages. If we ever have other stdout that starts with braces,
            # we will need to rethink this heuristic.
            if line.startswith("{"):
                emf = json.loads(line)

                if reemit:
                    assert tag is not None

                    emf["git_commit_id"] = str(tag)
                    emit_raw_emf(emf)

                dimensions, result = process_log_entry(emf)

                if not dimensions:
                    continue

                dimension_set = frozenset(dimensions.items())

                if dimension_set not in processed_emf:
                    processed_emf[dimension_set] = result
                else:
                    # If there are many data points for a metric, they will be split across
                    # multiple EMF log messages. We need to reassemble :(
                    assert (
                        processed_emf[dimension_set].keys() == result.keys()
                    ), f"Found incompatible metrics associated with dimension set {dimension_set}: {processed_emf[dimension_set].keys()} in one EMF message, but {result.keys()} in another."

                    for metric, (values, unit) in processed_emf[dimension_set].items():
                        assert result[metric][1] == unit

                        values.extend(result[metric][0])

    return processed_emf


def uninteresting_dimensions(processed_emf):
    """
    Computes the set of cloudwatch dimensions that only ever take on a
    single value across the entire dataset.
    """
    values_per_dimension = defaultdict(set)

    for dimension_set in processed_emf:
        for dimension, value in dimension_set:
            values_per_dimension[dimension].add(value)

    uninteresting = set()

    for dimension, distinct_values in values_per_dimension.items():
        if len(distinct_values) == 1:
            uninteresting.add(dimension)

    return uninteresting


def collect_data(tag: str, binary_dir: Path, pytest_opts: str):
    """
    Executes the specified test using the provided firecracker binaries and
    stores results into the `test_results/tag` directory
    """
    binary_dir = binary_dir.resolve()

    print(f"Collecting samples with {binary_dir}")
    test_report_path = f"test_results/{tag}/test-report.json"
    subprocess.run(
        f"./tools/test.sh --binary-dir={binary_dir} {pytest_opts} -m '' --json-report-file=../{test_report_path}",
        env=os.environ
        | {
            "AWS_EMF_ENVIRONMENT": "local",
            "AWS_EMF_NAMESPACE": "local",
        },
        check=True,
        shell=True,
    )

    return load_data_series(Path(test_report_path), binary_dir, reemit=True)


def analyze_data(
    processed_emf_a,
    processed_emf_b,
    p_thresh,
    strength_abs_thresh,
    noise_threshold,
    *,
    n_resamples: int = 9999,
):
    """
    Analyzes the A/B-test data produced by `collect_data`, by performing regression tests
    as described this script's doc-comment.

    Returns a mapping of dimensions and properties/metrics to the result of their regression test.
    """
    assert set(processed_emf_a.keys()) == set(
        processed_emf_b.keys()
    ), "A and B run produced incomparable data. This is a bug in the test!"

    results = {}

    metrics_logger = get_metrics_logger()

    for prop_name, prop_val in global_props.__dict__.items():
        metrics_logger.set_property(prop_name, prop_val)

    for dimension_set in processed_emf_a:
        metrics_a = processed_emf_a[dimension_set]
        metrics_b = processed_emf_b[dimension_set]

        assert set(metrics_a.keys()) == set(
            metrics_b.keys()
        ), "A and B run produced incomparable data. This is a bug in the test!"

        for metric, (values_a, unit) in metrics_a.items():
            result = check_regression(
                values_a, metrics_b[metric][0], n_resamples=n_resamples
            )

            metrics_logger.set_dimensions({"metric": metric, **dict(dimension_set)})
            metrics_logger.put_metric("p_value", float(result.pvalue), "None")
            metrics_logger.put_metric("mean_difference", float(result.statistic), unit)
            metrics_logger.set_property("data_a", values_a)
            metrics_logger.set_property("data_b", metrics_b[metric][0])
            metrics_logger.flush()

            results[dimension_set, metric] = (result, unit)

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

        values_a = processed_emf_a[dimension_set][metric][0]
        baseline_mean = statistics.mean(values_a)

        relative_changes_by_metric[metric].append(result.statistic / baseline_mean)

        if result.pvalue < p_thresh and abs(result.statistic) > strength_abs_thresh:
            failures.append((dimension_set, metric, result, unit))

            relative_changes_significant[metric].append(
                result.statistic / baseline_mean
            )

    messages = []
    do_not_print_list = uninteresting_dimensions(processed_emf_a)
    for dimension_set, metric, result, unit in failures:
        # Sanity check as described above
        if abs(statistics.mean(relative_changes_by_metric[metric])) <= noise_threshold:
            continue

        # No data points for this metric were deemed significant
        if metric not in relative_changes_significant:
            continue

        # The significant data points themselves are above the noise threshold
        if abs(statistics.mean(relative_changes_significant[metric])) > noise_threshold:
            old_mean = statistics.mean(processed_emf_a[dimension_set][metric][0])
            new_mean = statistics.mean(processed_emf_b[dimension_set][metric][0])

            msg = (
                f"\033[0;32m[Firecracker A/B-Test Runner]\033[0m A/B-testing shows a change of "
                f"{format_with_reduced_unit(result.statistic, unit)}, or {result.statistic / old_mean:.2%}, "
                f"(from {format_with_reduced_unit(old_mean, unit)} to {format_with_reduced_unit(new_mean, unit)}) "
                f"for metric \033[1m{metric}\033[0m with \033[0;31m\033[1mp={result.pvalue}\033[0m. "
                f"This means that observing a change of this magnitude or worse, assuming that performance "
                f"characteristics did not change across the tested commits, has a probability of {result.pvalue:.2%}. "
                f"Tested Dimensions:\n{json.dumps({k: v for k, v in dimension_set if k not in do_not_print_list}, indent=2, sort_keys=True)}"
            )
            messages.append(msg)

    assert not messages, "\n" + "\n".join(messages)
    print("No regressions detected!")


def ab_performance_test(
    a_revision: Path,
    b_revision: Path,
    pytest_opts,
    p_thresh,
    strength_abs_thresh,
    noise_threshold,
):
    """Does an A/B-test of the specified test with the given firecracker/jailer binaries"""

    return binary_ab_test(
        lambda bin_dir, is_a: collect_data(is_a and "A" or "B", bin_dir, pytest_opts),
        lambda ah, be: analyze_data(
            ah,
            be,
            p_thresh,
            strength_abs_thresh,
            noise_threshold,
            n_resamples=int(100 / p_thresh),
        ),
        a_directory=a_revision,
        b_directory=b_revision,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Executes Firecracker's A/B testsuite across the specified commits"
    )
    subparsers = parser.add_subparsers(help="commands", dest="command", required=True)
    run_parser = subparsers.add_parser(
        "run",
        help="Run an specific test of our test suite as an A/B-test across two specified commits",
    )
    run_parser.add_argument(
        "a_revision",
        help="Directory containing firecracker and jailer binaries to be considered the performance baseline",
        type=Path,
    )
    run_parser.add_argument(
        "b_revision",
        help="Directory containing firecracker and jailer binaries whose performance we want to compare against the results from a_revision",
        type=Path,
    )
    run_parser.add_argument(
        "--pytest-opts",
        help="Parameters to pass through to pytest, for example for test selection",
        required=True,
    )
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze the results of two manually ran tests based on their test-report.json files",
    )
    analyze_parser.add_argument(
        "report_a",
        help="The path to the test-report.json file of the baseline run",
        type=Path,
    )
    analyze_parser.add_argument(
        "report_b",
        help="The path to the test-report.json file of the run whose performance we want to compare against report_a",
        type=Path,
    )
    parser.add_argument(
        "--significance",
        help="The p-value threshold that needs to be crossed for a test result to be considered significant",
        type=float,
        default=0.01,
    )
    parser.add_argument(
        "--absolute-strength",
        help="The minimum absolute delta required before a regression will be considered valid",
        type=float,
        default=0.0,
    )
    parser.add_argument(
        "--noise-threshold",
        help="The minimal delta which a metric has to regress on average across all tests that emit it before the regressions will be considered valid.",
        type=float,
        default=0.05,
    )
    args = parser.parse_args()

    if args.command == "run":
        ab_performance_test(
            args.a_revision,
            args.b_revision,
            args.pytest_opts,
            args.significance,
            args.absolute_strength,
            args.noise_threshold,
        )
    else:
        data_a = load_data_series(args.report_a)
        data_b = load_data_series(args.report_b)

        analyze_data(
            data_a,
            data_b,
            args.significance,
            args.absolute_strength,
            args.noise_threshold,
        )
