# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Wrapper over an http session with timed requests."""

import requests_unixsocket

from framework import decorators


class Session(requests_unixsocket.Session):
    """Wrapper over requests_unixsocket.Session limiting the call duration.

    Only the API calls relevant to Firecracker (GET, PUT, PATCH) are
    implemented.
    """

    def __init__(self):
        """Create a Session object and set the is_good_response callback."""
        super(Session, self).__init__()

        def is_good_response(response: int):
            """Return `True` for all HTTP 2xx response codes."""
            return 200 <= response < 300

        self.is_good_response = is_good_response

    @decorators.timed_request
    def get(self, url, **kwargs):
        """Wrap the GET call with duration limit."""
        return super(Session, self).get(url, **kwargs)

    @decorators.timed_request
    def patch(self, url, data=None, **kwargs):
        """Wrap the PATCH call with duration limit."""
        return super(Session, self).patch(url, data=data, **kwargs)

    @decorators.timed_request
    def put(self, url, data=None, **kwargs):
        """Wrap the PUT call with duration limit."""
        return super(Session, self).put(url, data=data, **kwargs)
