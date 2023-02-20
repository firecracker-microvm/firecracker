# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Python."""

import sys

from subprocess import run


def test_python_pylint():
    """
    Test that python code passes linter checks.

    @type: build
    """
    # List of linter commands that should be executed for each file
    linter_cmd = (
        # Pylint
        "pylint --jobs=0 --persistent=no --score=no "
        '--output-format=colorized --attr-rgx="[a-z_][a-z0-9_]{1,30}$" '
        '--argument-rgx="[a-z_][a-z0-9_]{1,35}$" '
        '--variable-rgx="[a-z_][a-z0-9_]{1,30}$" --disable='
        "fixme,too-many-instance-attributes,import-error,"
        "too-many-locals,too-many-arguments,consider-using-f-string,"
        "consider-using-with,implicit-str-concat,line-too-long,"
        "broad-except,duplicate-code tests tools .buildkite/*.py"
    )
    run(
        linter_cmd,
        # we let pytest capture stdout/stderr for us
        stdout=sys.stdout,
        stderr=sys.stderr,
        shell=True,
        cwd="..",
        check=True,
    )
