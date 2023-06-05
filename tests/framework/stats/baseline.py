# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Module for common statistic tests baselines providers."""

from abc import ABC, abstractmethod
from collections import defaultdict

from framework.properties import global_props
from framework.utils import DictQuery


# pylint: disable=R0903
class Provider(ABC):
    """Baselines provider abstract class."""

    def __init__(self, baselines: DictQuery):
        """Block baseline provider initialization."""
        self._baselines = baselines

    @abstractmethod
    def get(self, ms_name: str, st_name: str) -> dict:
        """Return the baselines corresponding to the `ms_name` and `st_name`...

        ...combination.
        """

    def read_baseline(self, data: dict):
        """
        Read baseline data from a dictionary
        """
        baselines = defaultdict(dict)
        for instance, cpus in data["hosts"]["instances"].items():
            for cpu in cpus["cpus"]:
                cpu_model = cpu["model"]
                for baseline, val in cpu["baselines"].items():
                    baselines[instance, cpu_model][baseline] = val
        return {
            "baselines": baselines.get((global_props.instance, global_props.cpu_model)),
            "model": global_props.cpu_model,
        }
