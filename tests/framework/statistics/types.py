# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for common types definitions."""

from collections import namedtuple, defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import List
from .criteria import ComparisonCriteria
from .function import StatisticFunction, Max, Min, \
    Stddev, Percentile50, Percentile90, Percentile99, Avg

MeasurementDef = namedtuple("MeasurementDefinition", "name unit")


class DefaultStat(Enum):
    """Default statistics."""

    MAX = (1, "max")
    MIN = (2, "min")
    AVG = (3, "avg")
    STDDEV = (4, "stddev")
    P50 = (5, "p50")
    P90 = (6, "p90")
    P99 = (7, "p99")


@dataclass
class StatisticDef:
    """Statistic definition data class."""

    name: str
    measurement_name: str
    func_cls: StatisticFunction
    criteria: ComparisonCriteria = None

    @classmethod
    def max(cls, measurement_name: str, criteria: ComparisonCriteria):
        """Return max statistics definition."""
        return StatisticDef(DefaultStat.MAX.name,
                            measurement_name,
                            Max,
                            criteria)

    @classmethod
    def min(cls, measurement_name: str, criteria: ComparisonCriteria):
        """Return min statistics definition."""
        return StatisticDef(DefaultStat.MIN.name,
                            measurement_name,
                            Min,
                            criteria)

    @classmethod
    def avg(cls, measurement_name, criteria):
        """Return average statistics definition."""
        return StatisticDef(DefaultStat.AVG.name,
                            measurement_name,
                            Avg,
                            criteria)

    @classmethod
    def stddev(cls, measurement_name: str, criteria: ComparisonCriteria):
        """Return standard deviation statistics definition."""
        return StatisticDef(DefaultStat.STDDEV.name,
                            measurement_name,
                            Stddev,
                            criteria)

    @classmethod
    def p50(cls, measurement_name: str, criteria: ComparisonCriteria):
        """Return 50th percentile statistics definition."""
        return StatisticDef(DefaultStat.P50.name,
                            measurement_name,
                            Percentile50,
                            criteria)

    @classmethod
    def p90(cls, measurement_name: str, criteria: ComparisonCriteria):
        """Return 90th percentile statistics definition."""
        return StatisticDef(DefaultStat.P90.name,
                            measurement_name,
                            Percentile90,
                            criteria)

    @classmethod
    def p99(cls, measurement_name: str, criteria: ComparisonCriteria):
        """Return 99th percentile statistics definition."""
        return StatisticDef(DefaultStat.P99.name,
                            measurement_name,
                            Percentile99,
                            criteria)

    @classmethod
    def defaults(cls,
                 measurement_name: str,
                 pass_criteria: dict = None) \
            -> List['StatisticDef']:
        """Return list with default statistics definitions."""
        if pass_criteria is None:
            pass_criteria = defaultdict()
        else:
            pass_criteria = defaultdict(None, pass_criteria)

        return [
            cls.max(measurement_name,
                    pass_criteria.get(DefaultStat.MAX.name)),
            cls.min(measurement_name,
                    pass_criteria.get(DefaultStat.MIN.name)),
            cls.avg(measurement_name,
                    pass_criteria.get(DefaultStat.AVG.name)),
            cls.stddev(measurement_name,
                       pass_criteria.get(DefaultStat.STDDEV.name)),
            cls.p50(measurement_name,
                    pass_criteria.get(DefaultStat.P50.name)),
            cls.p90(measurement_name,
                    pass_criteria.get(DefaultStat.P90.name)),
            cls.p99(measurement_name,
                    pass_criteria.get(DefaultStat.P99.name))
        ]
