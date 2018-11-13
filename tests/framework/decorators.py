# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Module for declaring decorators used throughout integration tests."""


def test_context(cap, count=1):
    """Set the image capability and vm count attribute for individual tests."""
    def wrap(func):
        setattr(func, '_capability', cap)
        setattr(func, '_pool_size', count)
        return func
    return wrap
