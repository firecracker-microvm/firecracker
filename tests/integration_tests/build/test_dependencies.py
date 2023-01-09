# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Enforces controls over dependencies."""

import os
import ast

import pytest

from framework import utils
from host_tools import proc


pytestmark = pytest.mark.skipif(
    "Intel" not in proc.proc_type(), reason="test only runs on Intel"
)


def test_licenses():
    """Ensure license compatibility for Firecracker.

    For a list of currently allowed licenses checkout deny.toml in
    the root directory.

    @type: build
    """
    toml_file = os.path.normpath(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../Cargo.toml")
    )
    utils.run_cmd("cargo deny --manifest-path {} check licenses".format(toml_file))


@pytest.mark.parametrize("dep_file", ["framework/dependencies.txt"])
def test_num_dependencies(dep_file):
    """Enforce minimal dependency check.

    @type: build
    """
    _, stdout, _ = utils.run_cmd("cargo tree --prefix none -e no-dev " "--workspace")
    deps = stdout.splitlines()

    current_deps = set()
    # cargo tree displays a tree of dependencies which means
    # some of them will repeat. Below is a mechanism for filtering
    # unique dependencies.
    # cargo tree tries to display a (*) at the end of each non-leaf dependency
    # that was already encountered (crates without dependencies, such as libc
    # appear multiple times).
    for line in deps:
        if line and "(*)" not in line:
            # only care about dependency name, not version/path/github repo
            current_deps.add(line.split()[0])

    # Use the code below to update the expected dependencies.
    # with open(dep_file, "w", encoding='utf-8') as prev_deps:
    #     prev_deps.write(repr(sorted(current_deps)).replace(',', ',\n'))

    with open(dep_file, encoding="utf-8") as prev_deps:
        prev_deps = ast.literal_eval(prev_deps.read())

    difference = current_deps - set(prev_deps)

    if difference:
        assert (
            False
        ), f"New build dependencies detected. Is this expected? New dependencies {difference}"
