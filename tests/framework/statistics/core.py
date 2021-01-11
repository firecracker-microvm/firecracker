# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core module for statistics component management."""


from datetime import datetime
from collections import namedtuple, defaultdict
import types
from typing_extensions import TypedDict

from framework.statistics.criteria import Failed
from framework.statistics.producer import Producer
from framework.statistics.consumer import Consumer


# pylint: disable=R0903
class Statistics(TypedDict):
    """Data class for aggregated statistic results."""

    name: str
    iterations: int
    results: dict
    custom: dict


Pipe = namedtuple("Pipe", "producer consumer")


class Core:
    """Base class for statistics core driver."""

    # pylint: disable=W0102
    def __init__(self, name, iterations, custom={}, check=True):
        """Core constructor."""
        self._pipes = defaultdict(Pipe)
        self._statistics = Statistics(name=name,
                                      iterations=iterations,
                                      results={},
                                      custom=custom)
        self._check = check

    def add_pipe(self, producer: Producer, consumer: Consumer, tag=None):
        """Add a new producer-consumer pipe."""
        if tag is None:
            tag = self._statistics['name'] + "_" + \
                str(datetime.timestamp(datetime.now()))
        self._pipes[tag] = Pipe(producer, consumer)

    def run_exercise(self) -> Statistics:
        """Drive the statistics producers until completion."""
        iterations = self._statistics['iterations']
        for tag, pipe in self._pipes.items():
            for iteration in range(iterations):
                raw_data = pipe.producer.produce()
                if isinstance(raw_data, types.GeneratorType):
                    for data in raw_data:
                        pipe.consumer.ingest(iteration, data)
                else:
                    pipe.consumer.ingest(iteration, raw_data)
            try:
                stats, custom = pipe.consumer.process(self._check)
            except Failed as err:
                assert False, f"Failed on '{tag}': {err.msg}"

            self._statistics['results'][tag] = stats

            # Custom information extracted from all the iterations.
            if len(custom) > 0:
                self._statistics['custom'][tag] = custom

        if not self._check:
            print(self._statistics)

        return self._statistics

    @property
    def name(self):
        """Return statistics name."""
        return self._statistics.name

    @name.setter
    def name(self, name):
        """Set statistics name."""
        self._statistics.name = name

    @property
    def iterations(self):
        """Return statistics iterations count."""
        return self._statistics.iterations

    @iterations.setter
    def iterations(self, iterations):
        """Set statistics iterations count."""
        self._statistics.iterations = iterations

    @property
    def custom(self):
        """Return statistics custom information."""
        return self._statistics.custom

    @custom.setter
    def custom(self, custom):
        """Set statistics custom information."""
        self._statistics.custom = custom

    @property
    def statistics(self):
        """Return statistics gathered so far."""
        return self._statistics
