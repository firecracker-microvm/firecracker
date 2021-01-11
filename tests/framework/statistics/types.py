# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for common types definitions."""

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import List
from .criteria import ComparisonCriteria
from .function import StatisticFunction, Max, Min, \
    Stddev, Percentile50, Percentile90, Percentile99, Avg, Sum, \
    GetFirstObservation


class DefaultMeasurement(Enum):
    """Default measurements."""

    CPU_UTILIZATION_VMM = 1
    CPU_UTILIZATION_VCPUS_TOTAL = 2


@dataclass
class MeasurementDef:
    """Measurement definition data class."""

    name: str
    unit: str

    @classmethod
    def cpu_utilization_vmm(cls):
        """Return vmm cpu utilization measurement definition."""
        return MeasurementDef(
            DefaultMeasurement.CPU_UTILIZATION_VMM.name.lower(),
            "percentage"
        )

    @classmethod
    def cpu_utilization_vcpus_total(cls):
        """Return vcpus total cpu utilization measurement definition."""
        return MeasurementDef(
            DefaultMeasurement.CPU_UTILIZATION_VCPUS_TOTAL.name.lower(),
            "percentage"
        )


@dataclass
class StatisticDef:
    """Statistic definition data class."""

    _name: str
    measurement_name: str
    func_cls: StatisticFunction
    criteria: ComparisonCriteria = None

    @classmethod
    def max(cls, ms_name: str,
            st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return max statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Max,
                            criteria)

    @classmethod
    def min(cls, ms_name: str,
            st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return min statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Min,
                            criteria)

    @classmethod
    def avg(cls, ms_name: str,
            st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return average statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Avg,
                            criteria)

    @classmethod
    def sum(cls, ms_name: str,
            st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return average statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Sum,
                            criteria)

    @classmethod
    def stddev(cls, ms_name: str,
               st_name: str = None,
               criteria: ComparisonCriteria = None):
        """Return standard deviation statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Stddev,
                            criteria)

    @classmethod
    def p50(cls, ms_name: str,
            st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return 50th percentile statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Percentile50,
                            criteria)

    @classmethod
    def p90(cls, ms_name: str,
            st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return 90th percentile statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Percentile90,
                            criteria)

    @classmethod
    def p99(cls, ms_name: str, st_name: str = None,
            criteria: ComparisonCriteria = None):
        """Return 99th percentile statistics definition."""
        return StatisticDef(st_name,
                            ms_name,
                            Percentile99,
                            criteria)

    @classmethod
    def get_first_observation(cls, ms_name: str,
                              st_name: str = None,
                              criteria: ComparisonCriteria = None):
        """Return first observation of the exercise."""
        return StatisticDef(st_name,
                            ms_name,
                            GetFirstObservation,
                            criteria)

    @classmethod
    def defaults(cls,
                 measurement_name: str,
                 functions: List[StatisticFunction],
                 pass_criteria: dict = None) \
            -> List['StatisticDef']:
        """Return list with default statistics definitions."""
        if pass_criteria is None:
            pass_criteria = defaultdict()
        else:
            pass_criteria = defaultdict(None, pass_criteria)

        default_stats = list()
        for function in functions:
            function_name = function.name()
            default_stats.append(
                getattr(StatisticDef, function_name)(
                    ms_name=measurement_name,
                    criteria=pass_criteria.get(function_name)
                ))
        return default_stats

    @property
    def name(self):
        """Return the name used to identify the statistic definition."""
        if not self._name:
            self._name = self.func_cls.name()
        return self._name
