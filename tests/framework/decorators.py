# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Module for declaring decorators used throughout integration tests."""

import time

from framework.defs import MAX_API_CALL_DURATION_MS


def timed_request(method):
    """Decorate functions to monitor their duration."""
    class ApiTimeoutException(Exception):
        """A custom exception containing the details of the failed API call."""

        def __init__(self, duration, method, resource, payload):
            """Compose the error message from the API call components."""
            super(ApiTimeoutException, self).__init__(
                'API call exceeded maximum duration: {:.2f} ms.\n'
                'Call: {} {} {}'.format(duration, method, resource, payload)
            )

    def timed(*args, **kwargs):
        """Raise an exception if method's duration exceeds the max value."""
        start = time.time()
        result = method(*args, **kwargs)
        duration_ms = (time.time() - start) * 1000

        if duration_ms > MAX_API_CALL_DURATION_MS:
            try:
                # The positional arguments are:
                # 1. The Session object
                # 2. The URL from which we extract the resource for readability
                resource = args[1][(args[1].rfind("/")):]
            except IndexError:
                # Ignore formatting errors.
                resource = ''

            # The payload is JSON-encoded and passed as an argument.
            payload = kwargs['json'] if 'json' in kwargs else ''

            raise ApiTimeoutException(
                duration_ms,
                method.__name__.upper(),
                resource,
                payload
            )

        return result

    return timed


def test_context(cap, count=1):
    """Set the image capability and vm count attribute for individual tests."""
    def wrap(func):
        setattr(func, '_capability', cap)
        setattr(func, '_pool_size', count)
        return func
    return wrap
