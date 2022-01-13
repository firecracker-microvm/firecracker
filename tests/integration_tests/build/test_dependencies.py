# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Enforces controls over dependencies."""

import os
import ast
import pytest
from framework import utils


def test_licenses():
    """Ensure license compatibility for Firecracker.

    For a list of currently allowed licenses checkout deny.toml in
    the root directory.

    @type: build
    """
    toml_file = os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            '../../../Cargo.toml')
    )
    utils.run_cmd('cargo deny --manifest-path {} check licenses'.
                  format(toml_file))


@pytest.mark.parametrize(
    "dep_file",
    ["framework/dependencies.txt"]
)
def test_num_dependencies(dep_file):
    """Enforce minimal dependency check.

    @type: build
    """
    _, stdout, _ = utils.run_cmd('cargo tree --prefix none -e no-dev '
                                 '--workspace')
    deps = stdout.splitlines()

    current_deps = set()
    # cargo tree displays a tree of dependencies which means
    # some of them will repeat. Below is a mechanism for filtering
    # unique dependencies.
    # cargo tree tries to display a (*) at the end of each dependency that
    # was already encountered but it does not do very well (libc appears
    # multiple times).
    for line in deps:
        if line and "(*)" not in line:
            current_deps.add(line)

    # Use the code below to update the expected dependencies.
    # with open(dep_file, "w", encoding='utf-8') as prev_deps:
    #     prev_deps.write(str(current_deps))

    with open(dep_file, encoding='utf-8') as prev_deps:
        prev_deps = ast.literal_eval(prev_deps.read())
    if len(current_deps) > len(prev_deps):
        difference = current_deps - set(prev_deps)
        msg = "The number of build dependencies has increased." \
              " Is this expected? New dependencies {}".\
            format(list(difference))
        assert False, msg
    elif len(current_deps) != len(prev_deps):
        msg = "The build dependencies have changed." \
              " Use the code above to modify the {} file.". \
            format(dep_file)
        assert False, msg
