# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust and Python."""

from subprocess import run, PIPE

import os

import pytest
import yaml


SUCCESS_CODE = 0


@pytest.mark.timeout(120)
def test_rust_style():
    """Fail if there's misbehaving Rust style in this repo."""
    # Check that the output is empty.
    process = run(
        'cargo fmt --all -- --check',
        shell=True,
        check=True,
        stdout=PIPE
    )
    # rustfmt prepends `"Diff in"` to the reported output.
    assert "Diff in" not in process.stdout.decode('utf-8')


@pytest.mark.timeout(120)
def test_python_style():
    """Fail if there's misbehaving Python style in the test system."""
    # Check style with pylint.
    # We are using `xargs` for propagating error code triggered by the
    # actual command to stderr.
    cmd = r'find ../ -type f -iname "*.py" -not -path "../build/*" ' \
          r'-print0 | ' \
          r'xargs -0 -n1 ' \
          r'python3 -m pylint --jobs=0 --persistent=no --score=no ' \
          r'--output-format=colorized --attr-rgx="[a-z_][a-z0-9_]{1,30}$" ' \
          r'--argument-rgx="[a-z_][a-z0-9_]{1,30}$" ' \
          r'--variable-rgx="[a-z_][a-z0-9_]{1,30}$" --disable=' \
          r'bad-continuation,fixme,too-many-instance-attributes,' \
          r'too-many-locals,too-many-arguments'
    run(
        cmd,
        shell=True,
        check=True
    )

    # Check style with flake8.
    # TODO: Uncomment this after https://gitlab.com/pycqa/flake8/issues/406 is
    # fixed
    # run('python3 -m flake8 ../', shell=True, check=True)

    # Check style with pycodestyle.
    cmd = r'python3 -m pycodestyle --show-pep8 --show-source ' \
          r'--exclude=../build ../'
    run(
        cmd,
        shell=True,
        check=True
    )

    # Check style with pydocstyle.
    # pydocstyle's --match-dir option appears to be broken, so we're using
    # `find` here to exclude the build/ dir.
    cmd = r'find ../ -type f -iname "*.py" -not -path "../build/*" ' \
          r'-print0 | ' \
          r'xargs -0 -n1 ' \
          r'python3 -m pydocstyle --explain --source'
    run(
        cmd,
        shell=True,
        check=True
    )


def test_rust_clippy():
    """Fails if clippy generates any error, warnings are ignored."""
    run(
        'cargo clippy --all-targets --all-features',
        shell=True,
        check=True,
        stdout=PIPE
    )


def test_yaml_style():
    """Fail if our swagger specification is malformed."""
    yaml_spec = os.path.normpath(
         os.path.join(os.getcwd(), '../api_server/swagger/firecracker.yaml')
     )
    with open(yaml_spec, 'r') as file_stream:
        try:
            yaml.safe_load(file_stream)
        # pylint: disable=broad-except
        except Exception as exception:
            print(str(exception))
