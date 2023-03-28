# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility classes to fetch baseline data"""


import glob
import json
import os
import re

from utils.defs import BASELINE_FILENAME_PATTERN


class InvalidFilenameError(Exception):
    """Error for invalid file name"""

    def __init__(self, fname):
        self._message = (
            f"{fname} does not match the pattern " f"`{BASELINE_FILENAME_PATTERN}`."
        )
        super().__init__(self._message)

    def __str__(self):
        return self._message


class BaselineFileFetcher:
    """Class for fetching baselines from file."""

    def __init__(self, fpath):
        """Initialize baseline fetcher"""
        fname = os.path.basename(fpath)
        match = re.match(BASELINE_FILENAME_PATTERN, fname)
        if match is None:
            raise InvalidFilenameError(fname)

        self._fpath = fpath
        self._fname = fname
        self._test = match.group(1)
        self._kernel = match.group(2)
        with open(fpath, "r", encoding="utf-8") as file:
            self._raw = json.load(file)

    @property
    def fpath(self):
        """Return path of baseline file"""
        return self._fpath

    @property
    def fname(self):
        """Return file name of baseline file"""
        return self._fname

    @property
    def test(self):
        """Return test type"""
        return self._test

    @property
    def kernel(self):
        """Return kernel version"""
        return self._kernel

    def get_baseline(self, instance, model):
        """Get baseline values by instance type and CPU model"""
        if instance not in self._raw["hosts"]["instances"]:
            return None

        baselines = list(
            filter(
                lambda cpu_baseline: cpu_baseline["model"] == model,
                self._raw["hosts"]["instances"][instance]["cpus"],
            )
        )

        if len(baselines) == 0:
            return None

        return baselines[0]["baselines"]

    def get_instances(self):
        """Get list of instances"""
        return list(self._raw["hosts"]["instances"].keys())

    def get_models(self, instance):
        """Get list of CPU models"""
        return [m["model"] for m in self._raw["hosts"]["instances"][instance]["cpus"]]

    def get_cpus(self):
        """Get list of CPUs"""
        result = []
        for instance, value in self._raw["hosts"]["instances"].items():
            cpus = value["cpus"]
            for cpu in cpus:
                result.append(
                    {
                        "instance": instance,
                        "model": cpu["model"],
                    }
                )
        return result


class BaselineDirectoryFetcher:
    """Class for fetching baselines from directory."""

    def __init__(self, dpath):
        paths = sorted(glob.glob(os.path.join(dpath, "*.json")))
        pattern = re.compile(BASELINE_FILENAME_PATTERN)
        paths = [path for path in paths if pattern.match(os.path.basename(path))]

        self._dpath = dpath
        self._fetchers = {}
        for path in paths:
            self._fetchers[path] = BaselineFileFetcher(path)

    @property
    def dpath(self):
        """Return path of directory"""
        return self._dpath

    @property
    def fetchers(self):
        """Return lists of fetchers"""
        return self._fetchers

    def get_fetcher(self, test, kernel):
        """Get fetcher with test type and kernel version"""
        fetchers = list(
            filter(
                lambda f: f.test == test and f.kernel == kernel,
                self._fetchers.values(),
            )
        )

        if len(fetchers) == 0:
            return None

        return fetchers[0]
