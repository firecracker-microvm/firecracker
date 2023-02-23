# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for statistical functions."""

from abc import ABC, abstractmethod
from pydoc import locate

# pylint: disable=E0611
from statistics import mean, stdev
from typing import Any, List


# pylint: disable=R0903
class FunctionFactory:
    """Function factory class."""

    @classmethod
    def get(cls, func_cls_name) -> "Function":
        """`func_cls_name` must be a valid function class name."""
        return locate(f"framework.stats.function.{func_cls_name}")


# pylint: disable=R0903
class Function(ABC):
    """Statistic function abstract class."""

    def __init__(self, name):
        """Initialize the statistic function."""
        self._name = name

    @abstractmethod
    def __call__(self, result: Any) -> Any:
        """Builtin function needs to be implemented."""

    @property
    def name(self) -> str:
        """Return the a name identifier for the class."""
        return self._name


# pylint: disable=R0903
class ValuePlaceholder(Function):
    """This function can be used as a placeholder for results consumption.

    When used, it will simply provide a no-op over the result passed to it.
    The data will be forwarded to the final statistics view as it is received.

    If used for each iteration of a statistical exercise, the function will
    retain only the result corresponding to the last iteration.
    """

    def __init__(self, name="result"):
        """Initialize the statistic function."""
        super().__init__(name)

    def __call__(self, result: Any) -> Any:
        """Get the value."""
        return result


# pylint: disable=R0903
class Min(Function):
    """A function which computes the minimum observation from a list of...

    ...observations.
    """

    def __init__(self, name="Min"):
        """Initialize the statistic function."""
        super().__init__(name)

    def __call__(self, result: Any) -> Any:
        """Get the minimum observation."""
        assert isinstance(result, list)
        return min(result)


# pylint: disable=R0903
class Max(Function):
    """A function which computes the maximum observation from a list of...

    ...observations.
    """

    def __init__(self, name="Max"):
        """Initialize the statistic function."""
        super().__init__(name)

    def __call__(self, result: Any) -> Any:
        """Get the maximum observation."""
        assert isinstance(result, list)
        return max(result)


# pylint: disable=R0903
class Avg(Function):
    """A function which computes the average of a list of observations."""

    def __init__(self, name="Avg"):
        """Initialize the statistic function."""
        super().__init__(name)

    def __call__(self, result: Any) -> Any:
        """Get the average."""
        assert isinstance(result, list)
        return mean(result)


# pylint: disable=R0903
class Sum(Function):
    """A function which computes the sum for a list of observations."""

    def __init__(self, name="Sum"):
        """Initialize the statistic function."""
        super().__init__(name)

    def __call__(self, result: Any) -> Any:
        """Get the sum."""
        assert isinstance(result, list)
        return sum(result)


# pylint: disable=R0903
class Stddev(Function):
    """A function which computes the standard deviation of a list of...

    ...observations.
    """

    def __init__(self, name="Stddev"):
        """Initialize the statistic function."""
        super().__init__(name)

    def __call__(self, result: Any) -> Any:
        """Get the stddev."""
        assert isinstance(result, list)
        assert len(result) > 0
        if len(result) == 1:
            return 0
        return stdev(result)


# pylint: disable=R0903
class Percentile(Function, ABC):
    """A function which computes the kth percentile of a list of...

    ...observations.
    """

    def __init__(self, k: int, name: str):
        """Initialize the function."""
        super().__init__(name)
        self.k = k

    def __call__(self, result: List) -> Any:
        """Get the kth percentile of the statistical exercise."""
        assert isinstance(result, list)
        if len(result) == 1:
            return result[0]

        length = len(result)
        result.sort()
        idx = length * self.k / 100
        if not idx.is_integer():
            return (result[int(idx)] + result[min((int(idx) + 1), length - 1)]) / 2

        return result[int(idx)]


class Percentile50(Percentile):
    """A function which computes the 50th percentile of a list of...

    ...observations.
    """

    def __init__(self, name="P50"):
        """Initialize the function."""
        super().__init__(50, name)


class Percentile90(Percentile):
    """A function which computes the 90th percentile of a list of...

    ...observations.
    """

    def __init__(self, name="P90"):
        """Initialize the statistic function."""
        super().__init__(90, name)


class Percentile99(Percentile):
    """A function which computes the 99th percentile of a list of...

    ...observations.
    """

    def __init__(self, name="P99"):
        """Initialize the statistic function."""
        super().__init__(99, name)
