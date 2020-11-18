# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for multiple statistics consumers."""

from abc import ABC, abstractmethod
from typing import Any
from collections import defaultdict
from .types import MeasurementDef, StatisticDef
from .criteria import Failed


class Consumer(ABC):
    """Base class for statistics aggregation class."""

    UNIT_KEY = "unit"
    DATA_KEY = "data"

    # pylint: disable=W0102
    def __init__(self,
                 consume_stats,
                 custom=dict()):
        """Initialize a consumer."""
        self._results = defaultdict()  # Aggregated results.
        self._measurements_defs = defaultdict(MeasurementDef)
        self._statistics_defs = defaultdict()
        self._consume_stats = consume_stats
        self._custom = custom
        self._statistics = dict()
        self._iteration = 0

    @abstractmethod
    def ingest(self, iteration: int, raw_data: Any):
        """Abstract method for ingesting the raw result."""

    def consume_stat(self, st_name: str, ms_name: str, value: Any):
        """Aggregate statistics."""
        results = self._results.get(ms_name)
        if not results:
            self._results[ms_name] = dict()
        st_data = self._results[ms_name].get(st_name)
        if not st_data:
            self._results[ms_name][st_name] = list()
        self._results[ms_name][st_name].append(value)

    def consume_measurement(self,
                            ms_name: str,
                            value: Any):
        """Aggregate measurement."""
        results = self._results.get(ms_name)
        if not results:
            self._results[ms_name] = dict()
            self._results[ms_name][self.DATA_KEY] = list()
        self._results[ms_name][self.DATA_KEY].append(value)

    def consume_custom(self, name, value: Any):
        """Aggregate custom information."""
        if not self._custom.get(self._iteration):
            self._custom[self._iteration] = dict()
        self._custom[self._iteration][name] = value

    def set_stat_def(self, value: StatisticDef):
        """Set statistics definition."""
        if not self._statistics_defs.get(value.measurement_name):
            self._statistics_defs[value.measurement_name] = dict()

        self._statistics_defs[value.measurement_name][value.name] = value

    def set_measurement_def(self, value: MeasurementDef):
        """Set measurement definition."""
        self._measurements_defs[value.name] = value

    def _validate(self):
        """Verify that the statistics/measurements correspondence...

        is backed by corresponding measurements definitions.
        """
        for ms_name in self._statistics_defs:
            if ms_name not in self._measurements_defs:
                return False

        if self._consume_stats:
            # Verify if the gathered results for a measurement are
            # backed by measurements definitions.
            for ms_name in self._results:
                if ms_name not in self._measurements_defs:
                    return False
                # Verify if the gathered statistics are backed by
                # statistics definitions.
                for st_name in self._results[ms_name]:
                    if st_name not in self._statistics_defs[ms_name]:
                        return False
        else:
            # Verify if the gathered measurements are backed by
            # measurements definitions.
            for ms_name in self._results:
                if ms_name not in self._measurements_defs:
                    return False

            # Verify if the defined statistics have corresponding
            # gathered measurements.
            for ms_name in self._statistics_defs:
                if ms_name not in self._results:
                    return False

        return True

    def process(self) -> (dict, dict):
        """Generate statistics as a dictionary."""
        assert self._validate()
        # Generate consumer stats.
        for ms_name in self._statistics_defs:
            self._statistics.setdefault(ms_name, {})[self.UNIT_KEY] \
                = self._measurements_defs[ms_name].unit
            for st_name in self._statistics_defs[ms_name]:
                # We can either consume directly statistics, or compute them
                # based on measurements.
                stat = self._statistics_defs[ms_name][st_name]
                if self._consume_stats:
                    self._statistics[ms_name][st_name] = \
                        stat.func_cls(self._results[ms_name][st_name])()
                else:
                    self._statistics[ms_name][st_name] = \
                        stat.func_cls(self._results[ms_name][self.DATA_KEY])()

                # Check pass criteria.
                if stat.criteria:
                    res = self._statistics[ms_name][st_name]
                    try:
                        stat.criteria.check(res)
                    except Failed as err:
                        raise Failed(msg=f"'{ms_name}/{st_name}': {err.msg}")

        return self._statistics, self._custom


class LambdaConsumer(Consumer):
    """Consumer which executes a function in the ingestion step.

    The function called in the ingestion step must have the following
    signature: `def func(cons: Consumer, raw_output: Any, *args)`.
    """

    def __init__(self,
                 consume_stats,
                 func,
                 func_kwargs=None):
        """Initialize the LambdaConsumer."""
        super().__init__(consume_stats)
        assert callable(func)
        self._func = func
        self._func_kwargs = func_kwargs

    def ingest(self, iteration, raw_data):
        """Execute the function with or without arguments."""
        self._iteration = iteration
        if self._func_kwargs:
            self._func(self, raw_data, **self._func_kwargs)
        else:
            self._func(self, raw_data)
