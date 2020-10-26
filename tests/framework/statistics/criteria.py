# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module for comparision criteria."""

from numbers import Number
from abc import ABC, abstractmethod


class Failed(Exception):
    """Exception to be raised when criteria fails."""

    def __init__(self, msg=""):
        """Initialize the result."""
        self._msg = msg

    @property
    def msg(self):
        """Return the result message."""
        return self._msg

    @msg.setter
    def msg(self, msg):
        """Set the result message."""
        self._msg = msg


# pylint: disable=R0903
class ComparisonCriteria(ABC):
    """Comparison criteria between results and targets."""

    def __init__(self, name: str, target: Number):
        """Initialize the comparison criteria."""
        self.target = target
        self.name = name

    @abstractmethod
    def check(self, actual):
        """Compare the target and the actual."""


# pylint: disable=R0903
class GraterThan(ComparisonCriteria):
    """Greater than comparison criteria."""

    def __init__(self, target: Number):
        """Initialize the criteria."""
        super().__init__("GreaterThan", target)

    def check(self, actual):
        """Compare the target and the actual."""
        fail_msg = self.name + f" failed. Target: '{self.target} " \
                               f"vs Actual: '{actual}'."
        if self.target > actual:
            raise Failed(msg=fail_msg)


# pylint: disable=R0903
class LowerThan(ComparisonCriteria):
    """Lower than comparison criteria."""

    def __init__(self, target: Number):
        """Initialize the criteria."""
        super().__init__("LowerThan", target)

    def check(self, actual):
        """Compare the target and the actual."""
        fail_msg = self.name + f" failed. Target: '{self.target} " \
                               f"vs Actual: '{actual}'."
        if self.target < actual:
            raise Failed(msg=fail_msg)


# pylint: disable=R0903
class EqualWith(ComparisonCriteria):
    """Equal with comparison criteria."""

    def __init__(self, target: Number, tolerance: Number):
        """Initialize the criteria."""
        super().__init__("EqualWith", target)
        self.tolerance = tolerance

    def check(self, actual):
        """Compare the target and the actual."""
        fail_msg = self.name + f" failed. Target: '{self.target} +- " \
                               f"{self.tolerance}' " \
                               f"vs Actual: '{actual}'."
        if abs(self.target - actual) > self.tolerance:
            raise Failed(msg=fail_msg)
