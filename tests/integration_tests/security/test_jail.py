# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the jailer's behavior."""
import os


def test_default_chroot(test_microvm_with_ssh):
    """Test that the code base assigns a chroot if none is specified."""
    test_microvm = test_microvm_with_ssh

    # Start customizing arguments.
    # Test that firecracker's default chroot folder is indeed `/srv/jailer`.
    test_microvm.jailer.chroot_base = None

    test_microvm.spawn()

    # Test the expected outcome.
    assert os.path.exists(test_microvm.jailer.api_socket_path())


def test_empty_jailer_id(test_microvm_with_ssh):
    """Test that the jailer ID cannot be empty."""
    test_microvm = test_microvm_with_ssh

    # Set the jailer ID to None.
    test_microvm.jailer.jailer_id = ""

    # pylint: disable=W0703
    try:
        test_microvm.spawn()
        # If the exception is not thrown, it means that Firecracker was
        # started successfully, hence there's a bug in the code due to which
        # we can set an empty ID.
        assert False
    except Exception as err:
        expected_err = "Jailer error: Invalid instance ID: invalid len (0);" \
                       "  the length must be between 1 and 64"
        assert expected_err in str(err)
