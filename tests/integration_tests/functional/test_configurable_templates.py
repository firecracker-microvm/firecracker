# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that ensure the configurable CPU templates functionality."""


def test_api_happy_start(test_microvm_with_api):
    """
    Test that a regular microvm API config and boot sequence works.

    @type: functional
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    test_microvm.start()
