# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility classes to compare baseline data"""

import json
import math
import sys

from utils.defs import BASELINE_FILENAME_FORMAT, CODENAME2DICT
from utils.fetcher import BaselineDirectoryFetcher

EPS = sys.float_info.epsilon


class BaseComparator:
    """Base class for comparing baselines"""

    def __init__(self):
        self._result = {}

    @property
    def result(self):
        """Return result"""
        return self._result

    def calc_diff(self, bl1, bl2):
        """Calculate difference between two baselines."""
        diff = {}
        self._calc_diff(bl1, bl2, diff)
        return diff

    def _calc_diff(self, bl1, bl2, diff):
        """Go down nested structure and populate difference."""
        for key in bl1.keys() & bl2.keys():
            if key == "target":
                diff["target_diff_percentage"] = (
                    (bl2[key] + EPS) / (bl1[key] + EPS) - 1.0
                ) * 100.0
            elif key == "delta_percentage":
                diff["delta_percentage_diff"] = (
                    bl2["delta_percentage"] - bl1["delta_percentage"]
                )
            else:
                diff.setdefault(key, {})
                self._calc_diff(bl1[key], bl2[key], diff[key])

    def calc_stats(self, diff):
        """Calculate mean and unbiased standard deviation for each metric."""
        stats = {}

        for metric in diff.keys():
            stats[metric] = {}

            for key in ["target_diff_percentage", "delta_percentage_diff"]:
                aggregated = []
                self._aggregate_data(diff[metric], key, aggregated)

                mean = self._calc_mean(aggregated)
                stdev = self._calc_stdev(aggregated, mean)

                stats[metric][key] = {
                    "mean": mean,
                    "stdev": stdev,
                }

        return stats

    def _aggregate_data(self, data, key, result):
        """Aggregate data into list"""
        for value in data.values():
            if key in value:
                result.append(value[key])
            else:
                self._aggregate_data(value, key, result)

    def _calc_mean(self, data):
        """Calculate mean for given list."""
        if len(data) == 0:
            return None

        total = 0
        for value in data:
            total += value
        return total / len(data)

    def _calc_stdev(self, data, mean):
        """Calculate unbiased standard deviation for given list."""
        if len(data) == 0 or mean is None:
            return None

        var = 0
        for value in data:
            var += (value - mean) * (value - mean)
        return math.sqrt(var / (len(data) - 1))

    def dump_json(self, fpath):
        """Dump results to JSON file"""
        dumped = json.dumps(self._result, indent=4)
        with open(fpath, "w", encoding="utf-8") as file:
            file.write(dumped)


class DirectoryComparator(BaseComparator):
    """Class for comparing baselines between directories"""

    def __init__(self, dpath1, dpath2, tests, kernels, codenames):
        """Initialize 2 BaselineDirectoryFetcher"""
        super().__init__()
        self._dfetcher1 = BaselineDirectoryFetcher(dpath1)
        self._dfetcher2 = BaselineDirectoryFetcher(dpath2)
        self._tests = tests
        self._kernels = kernels
        self._codenames = codenames

    def compare(self, auxiliary=False):
        """Compare data between directories"""
        result = {
            "source": self._dfetcher1.dpath,
            "target": self._dfetcher2.dpath,
        }

        for test in self._tests:
            for kernel in self._kernels:
                fname = BASELINE_FILENAME_FORMAT.format(test=test, kernel=kernel)

                fetcher1 = self._dfetcher1.get_fetcher(test, kernel)
                if fetcher1 is None:
                    print(
                        f"{fname} not found in {self._dfetcher1.dpath}",
                        file=sys.stderr,
                    )
                    continue

                fetcher2 = self._dfetcher2.get_fetcher(test, kernel)
                if fetcher2 is None:
                    print(
                        f"{fname} not found in {self._dfetcher2.dpath}",
                        file=sys.stderr,
                    )
                    continue

                result[fname] = {
                    "test": test,
                    "kernel": kernel,
                    "cpus": [],
                }

                for codename in self._codenames:
                    cpu = CODENAME2DICT[codename]

                    baseline1 = fetcher1.get_baseline(cpu["instance"], cpu["model"])
                    if baseline1 is None:
                        print(
                            f"Baseline for {cpu['instance']} / {cpu['model']} not found"
                            f" in {fetcher1.fpath}.",
                            file=sys.stderr,
                        )
                        continue

                    baseline2 = fetcher2.get_baseline(cpu["instance"], cpu["model"])
                    if baseline2 is None:
                        print(
                            f"Baseline for {cpu['instance']} / {cpu['model']} not found"
                            f" in {fetcher2.fpath}.",
                            file=sys.stderr,
                        )
                        continue

                    diff = self.calc_diff(baseline1, baseline2)
                    stats = self.calc_stats(diff)

                    cpu_result = {
                        "instance": cpu["instance"],
                        "model": cpu["model"],
                        "stats": stats,
                    }
                    if auxiliary:
                        cpu_result["diff"] = diff

                    result[fname]["cpus"].append(cpu_result)

        self._result = result


class CpuComparator(BaseComparator):
    """Class for comparing baselines between CPUs"""

    def __init__(self, dpath, tests, kernels, codenames):
        """Initialize CPU comparator"""
        super().__init__()
        self._dpath = dpath
        self._tests = tests
        self._kernels = kernels
        self._codenames = codenames
        self._dfetcher = BaselineDirectoryFetcher(dpath)

    def compare(self, auxiliary=False):
        """Calculate differences and statistics based on the first CPU."""
        result = {}

        for test in self._tests:
            for kernel in self._kernels:
                fname = BASELINE_FILENAME_FORMAT.format(test=test, kernel=kernel)

                fetcher = self._dfetcher.get_fetcher(test, kernel)
                if fetcher is None:
                    print(
                        f"{fname} not found in {self._dfetcher.dpath}",
                        file=sys.stderr,
                    )
                    continue

                base_cpu = CODENAME2DICT[self._codenames[0]]
                base_instance = base_cpu["instance"]
                base_model = base_cpu["model"]
                base_baseline = fetcher.get_baseline(base_instance, base_model)
                if base_baseline is None:
                    print(
                        f"Baseline for {base_instance} / {base_model} not found"
                        f" in {fetcher.fpath}.",
                        file=sys.stderr,
                    )
                    continue

                # fmt: off
                result[fetcher.fpath] = {
                    "test": fetcher.test,
                    "kernel": fetcher.kernel,
                    "base": {
                        "instance": base_instance,
                        "model": base_model,
                    },
                    "stats": {},
                }
                if auxiliary:
                    result[fetcher.fpath]["diff"] = []
                # fmt: on

                for codename in self._codenames:
                    target_cpu = CODENAME2DICT[codename]
                    target_instance = target_cpu["instance"]
                    target_model = target_cpu["model"]

                    target_baseline = fetcher.get_baseline(
                        target_instance, target_model
                    )
                    if target_baseline is None:
                        print(
                            f"Baseline for {target_instance} / {target_model} not found"
                            f" in {fetcher.fpath}.",
                            file=sys.stderr,
                        )
                        continue

                    diff = self.calc_diff(base_baseline, target_baseline)
                    if auxiliary:
                        result[fetcher.fpath]["diff"].append(
                            {
                                "instance": target_instance,
                                "model": target_model,
                                "value": diff,
                            }
                        )

                    stats = self.calc_stats(diff)
                    for metric, data in stats.items():
                        result[fetcher.fpath]["stats"].setdefault(
                            metric,
                            {
                                "target_diff_percentage": [],
                                "delta_percentage_diff": [],
                            },
                        )

                        for key in ["target_diff_percentage", "delta_percentage_diff"]:
                            result[fetcher.fpath]["stats"][metric][key].append(
                                {
                                    "instance": target_instance,
                                    "model": target_model,
                                    "value": data[key],
                                }
                            )

        self._result = result
