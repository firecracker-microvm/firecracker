# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Enforces controls over dependencies."""

import os
import framework.utils as utils


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
