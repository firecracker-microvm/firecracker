# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Module to define utility abstractions to be used when working with...

...baselines in performance tests.
"""

from abc import abstractmethod, ABC
from typing import Any


# pylint: disable=R0903
class DictQuery:
    """Utility class to query python dicts key paths.

    The keys from the path must be `str`s.
    Example:
    > d = {
            "a": {
                "b": {
                    "c": 0
                }
            },
            "d": 1
      }
    > dq = DictQuery(d)
    > print(dq.get("a/b/c"))
    0
    > print(dq.get("d"))
    1
    """

    def __init__(self, d: dict):
        """Initialize the dict query."""
        self._inner = d

    def get(self, keys_path: str, default=None):
        """Retrieve value corresponding to the key path."""
        keys = keys_path.strip().split("/")
        if len(keys) < 1:
            return default

        result = self._inner.get(keys[0])
        for key in keys[1:]:
            if not result:
                return default

            result = result.get(key)

        return result

    def __str__(self):
        """Representation as a string."""
        return str(self._inner)


class BaselineProvider(ABC):
    """Abstraction class for ease of retrieving baselines."""

    def __init__(self, baselines: DictQuery):
        """Initialize the provider with the baselines data."""
        self._baselines = baselines

    @abstractmethod
    def target(self, key: str) -> Any:
        """Return the target corresponding to the baseline represented by...

        ...key. The key must be valid with respect to JSON pointer syntax.
        """

    @abstractmethod
    def delta(self, key: str) -> Any:
        """Return the delta corresponding to the baseline represented by...

        ...key. The key must be valid with respect to JSON pointer syntax.
        """
