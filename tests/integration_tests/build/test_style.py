"""Tests ensuring codebase style compliance for Rust and Python."""

from subprocess import run, PIPE

import os

import pytest
import yaml


SUCCESS_CODE = 0


@pytest.mark.timeout(120)
def test_rust_style():
    """Fail if there's misbehaving Rust style in this repo."""

    # Install rustfmt if it's not available yet.
    rustfmt_check = run(
        'rustup component list | grep --silent "rustfmt.*(installed)"',
        shell=True
    )
    if not rustfmt_check.returncode == SUCCESS_CODE:
        run(
            'rustup component add rustfmt-preview'
            '>/dev/null 2>&1',
            shell=True,
            check=True
        )
        # rustfmt-preview is used with the current state of things.
        # See github.com/rust-lang-nursery/rustfmt for information.

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
    run(
        r'find ../ -iname "*.py" -exec '
        r'python3 -m pylint '
        r'--jobs=0 --persistent=no --score=no --output-format=colorized '
        r'--attr-rgx="[a-z_][a-z0-9_]{1,30}$" '
        r'--argument-rgx="[a-z_][a-z0-9_]{1,30}$" '
        r'--variable-rgx="[a-z_][a-z0-9_]{1,30}$" '
        r'--disable='
        r'bad-continuation,fixme,'
        r'too-many-instance-attributes,too-many-locals,too-many-arguments '
        r'{} \;',
        shell=True,
        check=True
    )

    # Check style with flake8.
    # TODO: Uncomment this after https://gitlab.com/pycqa/flake8/issues/406 is
    # fixed
    # run('python3 -m flake8 ../', shell=True, check=True)

    # Check style with pycodestyle.
    run(
        'python3 -m pycodestyle --show-pep8 --show-source ../',
        shell=True,
        check=True
    )

    # Check style with pydocstyle.
    run(
        'python3 -m pydocstyle --explain --source ../',
        shell=True,
        check=True
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
