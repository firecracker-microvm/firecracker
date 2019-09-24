# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that ensures that all doctests pass at integration time."""

import host_tools.cargo_build as host  # pylint:disable=import-error


def test_doctests(test_session_root_path):
    """Run doc tests for all supported targets."""
    extra_env = ''
    extra_args = "--target x86_64-unknown-linux-gnu --doc --exclude cpuid"
    host.cargo_test(
        test_session_root_path,
        extra_args=extra_args,
        extra_env=extra_env
    )
