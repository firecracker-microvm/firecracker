#!/usr/bin/env python3
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Script for creating visualizations for A/B runs.

Usage:
ab_plot.py path_to_run_a path_to_run_b path_to_run_c ... --output_type pdf/table
"""

import argparse
import glob
import json
import time
from pathlib import Path
from typing import Callable, List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages

pd.set_option("display.float_format", "{:.2f}".format)


def check_regression(
    a_samples: List[float],
    b_samples: List[float],
    statistic: Callable = np.mean,
    *,
    n_resamples=9999,
):
    """
    Check if 2 sample groups have a statistically big enough difference
    """
    result = scipy.stats.permutation_test(
        (a_samples, b_samples),
        lambda x, y: statistic(y) - statistic(x),
        vectorized=False,
        n_resamples=n_resamples,
    )
    statistic_a = statistic(a_samples)

    return result.pvalue, result.statistic / statistic_a, result.statistic


def load_data(data_path: Path):
    """
    Recursively collects `metrics.json` files in provided path
    """
    data = []
    for name in glob.glob(f"{data_path}/**/metrics.json", recursive=True):
        with open(name, encoding="utf-8") as f:
            j = json.load(f)

        if "performance_test" not in j["dimensions"]:
            print(f"skipping: {name}")
            continue

        metrics = j["metrics"]
        # Move test name from dimensions into a separate column
        perf_test = j["dimensions"]["performance_test"]
        del j["dimensions"]["performance_test"]

        # These are host specific and will prevent comparison of
        # different hosts
        del j["dimensions"]["instance"]
        del j["dimensions"]["cpu_model"]
        del j["dimensions"]["host_kernel"]

        dimensions = frozenset(j["dimensions"].items())

        for m in metrics:
            if "cpu_utilization" in m:
                continue
            mm = metrics[m]
            unit = mm["unit"]
            values = mm["values"]
            for i, v in enumerate(values):
                data.append(
                    {
                        "index": i,
                        "test": perf_test,
                        "metric": m,
                        "value": v,
                        "unit": unit,
                        "dimensions": dimensions,
                    }
                )

    return data


def p50(a):
    """Returns 50th percentile of 1d-array a"""
    return np.percentile(a, 50)


def p90(a):
    """Returns 90th percentile of 1d-array a"""
    return np.percentile(a, 90)


def create_table(df: pd.DataFrame):
    """Create an html table per test in the data frame"""

    for test_value in df["test"].unique():
        df_test = df[df["test"] == test_value]

        # Split dimensions into separate columns
        df_expanded = df_test.copy()
        dim_data = []
        for _, row in df_expanded.iterrows():
            dim_dict = dict(row["dimensions"])
            dim_data.append(dim_dict)

        # Need to reset indexes because otherwise `pd.concat` will add NaN in all
        # rows where indexes differ
        dim_df = pd.DataFrame(dim_data).reset_index(drop=True)
        df_data = df_expanded.drop("dimensions", axis=1).reset_index(drop=True)
        df_expanded = pd.concat([df_data, dim_df], axis=1)

        # Use dimension columns as index
        dim_cols = sorted(list(dim_df.columns))
        df_pivoted = df_expanded.pivot_table(
            values=["value"],
            index=["metric", "unit"] + dim_cols,
            columns="group",
            aggfunc=[p50, p90],
        )

        # Add comparison columns for each group vs first group (A)
        groups = sorted(df_test["group"].unique())
        for baseline in groups:
            for group in groups:
                if group == baseline:
                    continue
                for stat in ["p50", "p90"]:
                    diff_col = (stat, "value", f"{baseline}->{group} %")
                    df_pivoted[diff_col] = (
                        (
                            df_pivoted[(stat, "value", group)]
                            - df_pivoted[(stat, "value", baseline)]
                        )
                        / df_pivoted[(stat, "value", baseline)]
                        * 100.0
                    )
                    diff_col = (stat, "value", f"{baseline}->{group} abs")
                    df_pivoted[diff_col] = (
                        df_pivoted[(stat, "value", group)]
                        - df_pivoted[(stat, "value", baseline)]
                    )

        # Sort columns to have a persistent table representation
        df_pivoted = df_pivoted[sorted(df_pivoted.columns)]

        test_output_path = f"{test_value}.html"
        with open(test_output_path, "w", encoding="UTF-8") as writer:
            writer.write("<br>")
            styled = df_pivoted.style.format(precision=2)
            styled = styled.set_table_attributes("border=1")
            styled = styled.set_table_styles(
                [{"selector": 'th:contains("->")', "props": [("min-width", "80px")]}]
            )

            # Apply color gradient to all comparison columns
            for baseline in groups:
                for group in groups:
                    if group == baseline:
                        continue
                    for stat in ["p50", "p90"]:
                        diff_col = (stat, "value", f"{baseline}->{group} %")
                        styled = styled.background_gradient(
                            subset=[diff_col], cmap="RdYlGn"
                        )

            writer.write(styled.to_html())
            writer.write("<br>")
        print(f"Ready: {test_output_path}")


def create_pdf(args, df: pd.DataFrame):
    """Create a pdf per test in the data frame"""

    sns.set_style("whitegrid")
    metrics = df["metric"].unique()
    n_groups = len(df["group"].unique())

    for test_value in df["test"].unique():
        test_output_path = f"{test_value}.pdf"
        with PdfPages(test_output_path) as pdf:
            df_test = df[df["test"] == test_value]
            for dim_value in df_test["dimensions"].unique():
                for metric in metrics:
                    metric_data = df_test[
                        (df_test["metric"] == metric)
                        & (df_test["dimensions"] == dim_value)
                    ]

                    if len(metric_data) == 0:
                        continue

                    additional_title = ""
                    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
                    if n_groups == 2:
                        # Check if difference is significant
                        a_values = metric_data[metric_data["group"] == "A"][
                            "value"
                        ].values
                        b_values = metric_data[metric_data["group"] == "B"][
                            "value"
                        ].values
                        pvalue, diff_rel, diff_abs = check_regression(
                            a_values, b_values
                        )

                        if (
                            pvalue <= 0.1
                            and abs(diff_rel) >= 0.05
                            and abs(diff_abs) >= 0.0
                        ):
                            fig.patch.set_facecolor("lightcoral")
                            additional_title = (
                                f"{diff_rel * 100:+.2f}% ({diff_abs:+.2f}) difference"
                            )

                    # Make a multi-line title since single line will be too long
                    dim_items = sorted(str(item) for item in dim_value)
                    dim_chunks = [
                        ", ".join(dim_items[i : i + 4])
                        for i in range(0, len(dim_items), 4)
                    ]
                    dim_str = "\n".join(dim_chunks)
                    title = f"{metric}\n{dim_str}\n{additional_title}"
                    if additional_title:
                        weight = "bold"
                    else:
                        weight = "normal"
                    fig.suptitle(title, fontsize=10, weight=weight)

                    sns.boxenplot(data=metric_data, x="group", y="value", ax=ax1)
                    ax1.set_ylabel(f"{metric} ({metric_data['unit'].iloc[0]})")

                    metric_data_indexed = metric_data.reset_index()
                    errorbar = (args.errorbar[0], int(args.errorbar[1]))
                    sns.lineplot(
                        data=metric_data_indexed,
                        x="index",
                        y="value",
                        hue="group",
                        ax=ax2,
                        errorbar=errorbar,
                    )
                    ax2.set_ylabel(f"{metric} ({metric_data['unit'].iloc[0]})")

                    plt.tight_layout()
                    pdf.savefig()
                    plt.close()
        print(f"Ready: {test_output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Executes Firecracker's A/B testsuite across the specified commits"
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Paths to directories with test runs",
        type=Path,
    )
    parser.add_argument(
        "--errorbar",
        nargs=2,
        default=["pi", "95"],
        help="Errorbar configuration for lineplot (type, value)",
    )
    parser.add_argument(
        "--output_type",
        default=["pdf"],
        help="Type of the output to generate",
    )
    args = parser.parse_args()

    # Data retrieval
    start_time = time.time()
    all_data = []
    for i, path in enumerate(args.paths):
        data = load_data(path)
        print(f"getting data {i} from {path}: {len(data)}")
        df = pd.DataFrame(data)
        df["group"] = chr(65 + i)  # A, B, C, D, ...
        all_data.append(df)
    print(f"Data retrieval: {time.time() - start_time:.2f}s")

    # Data processing
    start_time = time.time()
    df_combined = pd.concat(all_data, ignore_index=True)
    print(f"Data processing: {time.time() - start_time:.2f}s")

    # Plotting
    start_time = time.time()
    if args.output_type == "pdf":
        create_pdf(args, df_combined)
    if args.output_type == "table":
        create_table(df_combined)

    print(f"Plotting: {time.time() - start_time:.2f}s")
