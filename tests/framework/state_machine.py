# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Defines a stream based string matcher and a generic state object."""


# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903
class MatchStaticString:
    """Match a static string versus input."""

    # Prevent state objects from being collected by pytest.
    __test__ = False

    def __init__(self, match_string):
        """Initialize using specified match string."""
        self._string = match_string
        self._input = ""

    def match(self, input_char) -> bool:
        """
        Check if `_input` matches the match `_string`.

        Process one char at a time and build `_input` string.
        Preserve built `_input` if partially matches `_string`.
        Return True when `_input` is the same as `_string`.
        """
        self._input += str(input_char)
        if self._input == self._string[:len(self._input)]:
            if len(self._input) == len(self._string):
                self._input = ""
                return True
            return False

        self._input = self._input[1:]
        return False


class TestState(MatchStaticString):
    """Generic test state object."""

    # Prevent state objects from being collected by pytest.
    __test__ = False

    def __init__(self, match_string=''):
        """Initialize state fields."""
        MatchStaticString.__init__(self, match_string)
        print('\n*** Current test state: ', str(self), end='')

    def handle_input(self, microvm, input_char):
        """Handle input event and return next state."""

    def __repr__(self):
        """Leverages the __str__ method to describe the TestState."""
        return self.__str__()

    def __str__(self):
        """Return state name."""
        return self.__class__.__name__
