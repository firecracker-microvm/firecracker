# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Imported by pytest when running tests in this directory"""

import pytest

from framework.artifacts import firecracker_artifacts


# This fixture forces a Firecracker build, even if it doesn't get used.
# By placing it here instead of the top-level conftest.py we skip the build.
@pytest.fixture(params=firecracker_artifacts())
def firecracker_release(request, record_property):
    """Return all supported firecracker binaries."""
    firecracker = request.param
    record_property("firecracker_release", firecracker.name)
    return firecracker
