# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define data types and abstractions for parsers."""

from abc import abstractmethod, ABC
from collections.abc import Iterator
from typing import AnyStr

# pylint: disable=R0903


class FileDataProvider(Iterator):
    """File based data provider."""

    def __init__(self, file_path: str):
        """Construct the file based data provider."""
        self._file = open(file_path, "r")

    def __iter__(self) -> 'FileDataProvider':
        """Return the iterator object (self)."""
        return self

    def __next__(self) -> AnyStr:
        """Get a line of data from the file."""
        return self._file.readline()


class DataParser(ABC):
    """Abstract class to be used for baselines extraction."""

    @abstractmethod
    def parse(self) -> dict:
        """Parse the raw data and return baselines."""
