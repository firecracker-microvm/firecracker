# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Python."""

from framework import utils


def test_python_pylint():
    """
    Test that python code passes linter checks.

    @type: build
    """
    # List of linter commands that should be executed for each file
    linter_cmd = (
        # Pylint
        "python3 -m pylint --jobs=0 --persistent=no --score=no "
        '--output-format=colorized --attr-rgx="[a-z_][a-z0-9_]{1,30}$" '
        '--argument-rgx="[a-z_][a-z0-9_]{1,35}$" '
        '--variable-rgx="[a-z_][a-z0-9_]{1,30}$" --disable='
        "fixme,too-many-instance-attributes,import-error,"
        "too-many-locals,too-many-arguments,consider-using-f-string,"
        "consider-using-with,implicit-str-concat,line-too-long,broad-exception-raised"
    )

    # Get all *.py files from the project
    python_files = utils.get_files_from(
        find_path="..", pattern="*.py", exclude_names=["build", ".kernel", ".git"]
    )

    # Assert if somehow no python files were found
    assert len(python_files) != 0

    # Run commands
    utils.run_cmd_list_async([f"{linter_cmd} {fname}" for fname in python_files])
