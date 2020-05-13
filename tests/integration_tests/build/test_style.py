# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust and Python."""

import os
import platform

import pytest
import yaml

import framework.utils as utils

SUCCESS_CODE = 0


@pytest.mark.timeout(120)
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="no need to test it on multiple platforms"
)
def test_rust_style():
    """Fail if there's misbehaving Rust style in this repo."""
    # Check that the output is empty.
    _, stdout, _ = utils.run_cmd(
        'cargo fmt --all -- --check')

    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in stdout


@pytest.mark.timeout(120)
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="no need to test it on multiple platforms"
)
def test_python_style():
    """Fail if there's misbehaving Python style in the test system."""
    # List of linter commands that should be executed for each file
    linter_cmds = [
        # Pylint
        'python3 -m pylint --jobs=0 --persistent=no --score=no ' \
        '--output-format=colorized --attr-rgx="[a-z_][a-z0-9_]{1,30}$" ' \
        '--argument-rgx="[a-z_][a-z0-9_]{1,30}$" ' \
        '--variable-rgx="[a-z_][a-z0-9_]{1,30}$" --disable=' \
        'bad-continuation,fixme,too-many-instance-attributes,' \
        'too-many-locals,too-many-arguments',

        # pycodestyle
        'python3 -m pycodestyle --show-pep8 --show-source --exclude=../build',

        # pydocstyle
        "python3 -m pydocstyle --explain --source"]

    # Get all *.py files from the project
    python_files = utils.get_files_from(
        find_path="..",
        pattern="*.py",
        exclude_names=["build"])

    # Assert if somehow no python files were found
    assert len(python_files) != 0

    # Run commands
    utils.run_cmd_list_async([
        f"{cmd} {fname}" for cmd in linter_cmds for fname in python_files
    ])


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="no need to test it on multiple platforms"
)
def test_rust_clippy():
    """Fails if clippy generates any error, warnings are ignored."""
    utils.run_cmd(
        'cargo clippy --all --profile test -- -D warnings')


def check_swagger_style(yaml_spec):
    """Check if the swagger definition is correctly formatted."""
    with open(yaml_spec, 'r') as file_stream:
        try:
            yaml.safe_load(file_stream)
        # pylint: disable=broad-except
        except Exception as exception:
            print(str(exception))


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="no need to test it on multiple platforms"
)
def test_firecracker_swagger():
    """Fail if Firecracker swagger specification is malformed."""
    yaml_spec = os.path.normpath(
        os.path.join(os.getcwd(), '../src/api_server/swagger/firecracker.yaml')
    )
    check_swagger_style(yaml_spec)
