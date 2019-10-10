# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Rust and Python."""

from subprocess import run, PIPE

import os
import platform

import pytest
import yaml


SUCCESS_CODE = 0


@pytest.mark.timeout(120)
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="rustfmt is not available on Rust 1.38 on aarch64"
)
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
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="no need to test it on multiple platforms"
)
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


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="no need to test it on multiple platforms"
)
def test_rust_clippy():
    """Fails if clippy generates any error, warnings are ignored."""
    run(
        'cargo clippy --all --profile test -- -D warnings',
        shell=True,
        check=True,
        stdout=PIPE
    )


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
        os.path.join(os.getcwd(), '../api_server/swagger/firecracker.yaml')
    )
    check_swagger_style(yaml_spec)
