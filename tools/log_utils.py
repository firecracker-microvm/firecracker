#!/usr/bin/env python3

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""This script is intended to be an entry point for `devtool` script.

It provides the needed primitives for logging to standard output and error.
"""

import sys
from enum import Enum


MY_NAME = "[Firecracker tooling]"


class Colors(Enum):
    """Helper class for colored output encoding."""

    HEADER = '\033[95m'
    OKGREEN = '\033[32m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def _say(msg, msg_color, tag, tag_color, file, newline=True):
    if not file.isatty():
        return
    if msg_color is None:
        msg_color = ""
    if tag_color is None:
        tag_color = ""
    print(f"{tag_color}{tag}{Colors.ENDC.value} "
          f"{msg_color}{msg}{msg_color}{Colors.ENDC.value}",
          file=file, end="\n" if newline else "")


def say_info(msg, newline=True):
    """Send a decorated message to stdout, followed by a new line."""
    _say(msg, None, MY_NAME, Colors.OKGREEN.value, sys.stdout, newline)


def say_err(msg, newline=True):
    """Send a text message to stderr."""
    _say(msg, Colors.FAIL.value, MY_NAME, Colors.FAIL.value,
         sys.stderr, newline)


def say_warn(msg, newline=True):
    """Send a warning-highlighted text to stdout."""
    _say(msg, Colors.ENDC.value, MY_NAME, Colors.WARNING.value,
         sys.stdout, newline)


def die(msg, code=-1):
    """Exit with an error message and (optional) code."""
    say_err(msg)
    sys.exit(code)


def ok_or_die(msg, code):
    """Exit with an error message if the last exit code is not 0."""
    if code != 0:
        die(msg, code)
