# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core module for statistics component management."""


import types
from collections import defaultdict, namedtuple
from datetime import datetime
from typing import TypedDict

from framework.utils import ExceptionAggregator

from .consumer import Consumer, ProcessingException
from .producer import Producer


class CoreException(ExceptionAggregator):
    """Exception used to return core messages.

    The caller should handle the exception accordingly.
    """

    def __init__(self, result=None):
        """Initialize the exception."""
        super().__init__()
        self.result = result


class Result(TypedDict):
    """Data class for aggregated statistic results."""

    name: str
    iterations: int
    results: dict
    custom: dict


Pipe = namedtuple("Pipe", "producer consumer")


class Core:
    """Base class for statistics core driver."""

    # pylint: disable=W0102
    def __init__(self, name="<PLACEHOLDER>", iterations=1, custom={}):
        """Core constructor."""
        self._pipes = defaultdict(Pipe)
        self._result = Result(
            name=name, iterations=iterations, results={}, custom=custom
        )
        self._failure_aggregator = CoreException()
        self.metrics_test = None
        self.metrics = None
        self.check_baseline = True

    def add_pipe(self, producer: Producer, consumer: Consumer, tag=None):
        """Add a new producer-consumer pipe."""
        if tag is None:
            tag = self._result["name"] + "_" + str(datetime.timestamp(datetime.now()))
        self._pipes[tag] = Pipe(producer, consumer)

    def run_exercise(self, fail_fast=False) -> Result:
        """Drive the statistics producers until completion."""
        iterations = self._result["iterations"]

        for tag, pipe in self._pipes.items():
            for iteration in range(iterations):
                raw_data = pipe.producer.produce()
                if not isinstance(raw_data, types.GeneratorType):
                    raw_data = [raw_data]
                for data in raw_data:
                    raws = pipe.consumer.ingest(iteration, data)
                    if raws is not None:
                        dimensions = self.custom.copy()
                        test = tag.split("/")[-1]
                        dimensions["test"] = test
                        dimensions["performance_test"] = self.name
                        self.metrics.set_dimensions(dimensions)
                        for name, val, unit in raws:
                            self.metrics.put_metric(name, val, unit)
                            self.metrics.set_property("iteration", iteration)
                        self.metrics.flush()

            try:
                stats, custom = pipe.consumer.process(check=self.check_baseline)
            except (ProcessingException, AssertionError) as err:
                self._failure_aggregator.add_row(f"Failed on '{tag}':")
                self._failure_aggregator.add_row(err)
                stats = err.stats
                custom = err.custom
                if fail_fast:
                    raise self._failure_aggregator

            self._result["results"][tag] = stats

            # Custom information extracted from all the iterations.
            if len(custom) > 0:
                self._result["custom"][tag] = custom

        self.raise_if_regression()
        return self._result

    def raise_if_regression(self):
        """Raise an exception if there was an issue or a regression was
        detected.
        """
        if self._failure_aggregator.has_any():
            self._failure_aggregator.result = self._result
            # If we had Python 3.11 we could use ExceptionGroup
            raise self._failure_aggregator

    @property
    def name(self):
        """Return statistics name."""
        return self._result["name"]

    @name.setter
    def name(self, name):
        """Set statistics name."""
        self._result["name"] = name

    @property
    def iterations(self):
        """Return statistics iterations count."""
        return self._result["iterations"]

    @iterations.setter
    def iterations(self, iterations):
        """Set statistics iterations count."""
        self._result["iterations"] = iterations

    @property
    def custom(self):
        """Return statistics custom information."""
        return self._result["custom"]

    @custom.setter
    def custom(self, custom):
        """Set statistics custom information."""
        self._result["custom"] = custom

    @property
    def statistics(self):
        """Return statistics gathered so far."""
        return self._result
