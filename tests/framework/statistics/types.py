# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for common types definitions."""
from collections import defaultdict
from dataclasses import dataclass
from typing import List
from .criteria import ComparisonCriteria
from .function import Function


@dataclass
class MeasurementDef:
    """Measurement definition data class."""

    name: str
    unit: str
    statistics: List['StatisticDef']

    @classmethod
    def create_measurement(cls,
                           measurement_name: str,
                           unit: str,
                           st_functions: List[Function],
                           pass_criteria: dict = None) -> 'MeasurementDef':
        """
        Create a measurement based on the given params.

        The expected `pass_criteria` dict is a dictionary with the following
        format:
        {
            # Statistic name explicitly provided in statistics definitions or
            # inherited from statistic functions (e.g Avg, Min, Max etc.).
            "key": str,
            # The comparison criteria used for pass/failure.
            "value": statistics.criteria.ComparisonCriteria,
        }
        """
        if pass_criteria is None:
            pass_criteria = defaultdict()
        else:
            pass_criteria = defaultdict(None, pass_criteria)

        stats = list()
        for func in st_functions:
            stats.append(
                StatisticDef(
                    func=func,
                    pass_criteria=pass_criteria.get(func.name)
                ))

        return cls(measurement_name, unit, stats)


@dataclass
class StatisticDef:
    """Statistic definition data class."""

    func: Function
    pass_criteria: ComparisonCriteria = None

    @property
    def name(self) -> str:
        """Return the name used to identify the statistic definition."""
        return self.func.name
