# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for multiple statistics consumers."""

from abc import ABC, abstractmethod
from numbers import Number
from typing import Any, Callable
from collections import defaultdict
from .metadata import Provider as MetadataProvider
from .criteria import Failed
from .types import MeasurementDef


class Consumer(ABC):
    """Base class for statistics aggregation class."""

    UNIT_KEY = "_unit"
    DATA_KEY = "_data"

    # pylint: disable=W0102
    def __init__(self,
                 metadata_provider: MetadataProvider = None,
                 custom=None):
        """Initialize a consumer."""
        self._iteration = 0
        self._results = defaultdict()  # Aggregated results.
        self._custom = dict() if not custom else custom
        self._metadata_provider = metadata_provider

        self._measurements_defs = dict()
        if metadata_provider:
            self._measurements_defs = metadata_provider.measurements

        # Final statistics.
        self._statistics = dict()

    @abstractmethod
    def ingest(self, iteration: int, raw_data: Any):
        """Abstract method for ingesting the raw result."""

    def consume_data(self, ms_name: str, value: Number):
        """Aggregate measurement."""
        results = self._results.get(ms_name)
        if not results:
            self._results[ms_name] = dict()
            self._results[ms_name][self.DATA_KEY] = list()
        self._results[ms_name][self.DATA_KEY].append(value)

    def consume_stat(self, st_name: str, ms_name: str, value: Number):
        """Aggregate statistics."""
        results = self._results.get(ms_name)
        if not results:
            self._results[ms_name] = dict()
        self._results[ms_name][st_name] = value

    def consume_custom(self, name: str, value: Any):
        """Aggregate custom information."""
        if not self._custom.get(self._iteration):
            self._custom[self._iteration] = dict()

        if not self._custom[self._iteration].get(name):
            self._custom[self._iteration][name] = list()

        self._custom[self._iteration][name].append(value)

    def set_measurement_def(self, value: MeasurementDef):
        """Set measurement definition."""
        self._measurements_defs[value.name] = value

    def _validate(self):
        """Verify that the statistics/measurements correspondence...

        is backed by corresponding measurements definitions.
        """
        for ms_name in self._results:
            if ms_name not in self._measurements_defs:
                raise Exception(f"'{ms_name}' measurement does not have a "
                                "corresponding measurement definition.")

    def _reset(self):
        """Reset the results of this consumer, used in a previous exercise."""
        self._results = defaultdict()

    def process(self, check_criteria=True) -> (dict, dict):
        """Generate statistics as a dictionary."""
        self._validate()
        for ms_name in self._results:
            self._statistics.setdefault(ms_name, {})[self.UNIT_KEY] \
                = self._measurements_defs[ms_name].unit

            st_defs = self._measurements_defs[ms_name].statistics
            for st_def in st_defs:
                if st_def.name not in self._results[ms_name]:
                    assert Consumer.DATA_KEY in self._results[ms_name], \
                        "Results does not have extracted data points for" \
                        f" {ms_name} measurement."
                    self._statistics[ms_name][st_def.name] = \
                        st_def.func(self._results[ms_name][self.DATA_KEY])
                else:
                    self._statistics[ms_name][st_def.name] = self._results[
                        ms_name][st_def.name]

                pass_criteria = st_def.pass_criteria
                if pass_criteria and check_criteria:
                    res = self._statistics[ms_name][st_def.name]
                    try:
                        pass_criteria.check(res)
                    except Failed as err:
                        self._reset()
                        # pylint: disable=W0707
                        raise Failed(msg=f"'{ms_name}/{st_def.name}':"
                                         f" {err.msg}")

        self._reset()
        return self._statistics, self._custom


class LambdaConsumer(Consumer):
    """Consumer which executes a function in the ingestion step.

    The function called in the ingestion step must have the following
    signature: `def func_name(cons: Consumer, raw_output: Any, **kw_args)`.
    """

    def __init__(self,
                 func: Callable,
                 func_kwargs=None,
                 metadata_provider: MetadataProvider = None):
        """Initialize the LambdaConsumer."""
        super().__init__(metadata_provider)
        self._func = func
        self._func_kwargs = func_kwargs

    def ingest(self, iteration, raw_data):
        """Execute the function with or without arguments."""
        self._iteration = iteration
        if self._func_kwargs:
            self._func(self, raw_data, **self._func_kwargs)
        else:
            self._func(self, raw_data)
