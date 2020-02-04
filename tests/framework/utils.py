# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generic utility functions that are used in the framework."""
import re
import subprocess
import typing


def search_output_from_cmd(cmd: str,
                           find_regex: typing.Pattern) -> typing.Match:
    """
    Run a shell command and search a given regex object in stdout.

    If the regex object is not found, a RuntimeError exception is raised.

    :param cmd: command to run
    :param find_regex: regular expression object to search for
    :return: result of re.search()
    """
    # Run the given command in a shell
    out = subprocess.run(cmd, shell=True, check=True,
                         stdout=subprocess.PIPE).stdout.decode("utf-8")

    # Search for the object
    content = re.search(find_regex, out)

    # If the result is not None, return it
    if content:
        return content

    raise RuntimeError("Could not find '%s' in output for '%s'" %
                       (find_regex.pattern, cmd))
