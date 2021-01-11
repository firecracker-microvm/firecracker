# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for statistical functions."""


from abc import ABC, abstractmethod
from numbers import Number
from typing import Any, List
# pylint: disable=E0611
from statistics import mean, stdev


# pylint: disable=R0903
class StatisticFunction(ABC):
    """Statistic function abstract class."""

    def __init__(self, results: List[Number]):
        """Initialize the statistic function."""
        self.results = results

    @abstractmethod
    def __call__(self) -> Any:
        """Builtin function needs to be implemented."""

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """Return the name identifier for the class."""


# pylint: disable=R0903
class GetFirstObservation(StatisticFunction):
    """A function which return the first observation."""

    def __call__(self) -> Any:
        """Get the first result only."""
        assert len(self.results) > 0
        return self.results[0]

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `GetFirstObservation`."""
        return "get_first_observation"


# pylint: disable=R0903
class Min(StatisticFunction):
    """A function which computes the minimum observation from a list of...

    ...observations.
    """

    def __call__(self) -> Any:
        """Get the minimum observation."""
        return min(self.results)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Min`."""
        return "min"


# pylint: disable=R0903
class Max(StatisticFunction):
    """A function which computes the maximum observation from a list of...

    ...observations.
    """

    def __call__(self) -> Any:
        """Get the maximum observation."""
        return max(self.results)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Max`."""
        return "max"


# pylint: disable=R0903
class Avg(StatisticFunction):
    """A function which computes the average of a list of observations."""

    def __call__(self) -> Any:
        """Get the average."""
        return mean(self.results)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Avg`."""
        return "avg"


# pylint: disable=R0903
class Sum(StatisticFunction):
    """A function which computes the sum for a list of observations."""

    def __call__(self) -> Any:
        """Get the sum."""
        return sum(self.results)

    @classmethod
    def name(cls) -> str:
        """Return identifier for `Sum`."""
        return "sum"


# pylint: disable=R0903
class Stddev(StatisticFunction):
    """A function which computes the standard deviation of a list of...

    ...observations.
    """

    def __call__(self) -> Any:
        """Get the stddev."""
        assert len(self.results) > 0
        # pylint: disable=R0123
        if len(self.results) is 1:
            return self.results[0]
        return stdev(self.results)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Stddev`."""
        return "stddev"


# pylint: disable=R0903
class Percentile(StatisticFunction, ABC):
    """A function which computes the kth percentile of a list of...

    ...observations.
    """

    def __init__(self, results: List, k: int):
        """Initialize the function."""
        super().__init__(results)
        self.k = k

    def __call__(self) -> Any:
        """Get the kth percentile of the statistical exercise."""
        # pylint: disable=R0123
        if len(self.results) is 1:
            return self.results[0]

        length = len(self.results)
        self.results.sort()
        idx = length * self.k / 100
        if idx is not int(idx):
            return (self.results[int(idx)] + self.results[(int(idx) + 1)]) / 2

        return self.results[int(idx)]


class Percentile50(Percentile):
    """A function which computes the 50th percentile of a list of...

    ...observations.
    """

    def __init__(self, results: List):
        """Initialize the function."""
        super().__init__(results, 50)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Percentile50`."""
        return "p50"


class Percentile90(Percentile):
    """A function which computes the 90th percentile of a list of...

    ...observations.
    """

    def __init__(self, results: List):
        """Initialize the function."""
        super().__init__(results, 90)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Percentile90`."""
        return "p90"


class Percentile99(Percentile):
    """A function which computes the 99th percentile of a list of...

    ...observations.
    """

    def __init__(self, results: List):
        """Initialize the function."""
        super().__init__(results, 99)

    @classmethod
    def name(cls) -> str:
        """Return an identifier for `Percentile99`."""
        return "p99"
