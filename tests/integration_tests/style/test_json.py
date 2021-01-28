# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for JSON linter checks."""

import framework.utils as utils
import json


def test_json_style():
    """Fail if the repository contains malformed JSON in .json files"""

    # Get all *.json files from the project
    json_files = utils.get_files_from(
        find_path="..",
        pattern="*.json",
        exclude_names=["build"])

    assert len(json_files) != 0

    # for each .json file we find, check that
    # it can be parsed as JSON
    for file_name in json_files:
        assert is_json_file_valid(file_name)


def is_json_file_valid(file_path):
    """returns whether or not the file at the specified path contains valid JSON"""

    with open(file_path, 'r') as file_stream:
        try:
            json.load(file_stream)

            # no exception was thrown
            # therefore file's contents are valid JSON
            return True
        except json.JSONDecodeError:
            # json failed to decode
            return False
