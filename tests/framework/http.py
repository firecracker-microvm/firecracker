# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Wrapper over an http session with timed requests."""
# pylint: disable=unused-import
import requests
from requests_unixsocket import DEFAULT_SCHEME, UnixAdapter


class Session(requests.Session):
    """Wrapper over requests_unixsocket.Session limiting the call duration.

    Only the API calls relevant to Firecracker (GET, PUT, PATCH) are
    implemented.
    """

    def __init__(self):
        """Create a Session object and set the is_good_response callback."""
        super().__init__()

        # 'UnixAdapter` saves in the pool at most 'pool_connections'
        # connections. When a new request is made, the adapter tries to match
        # that request with an already existing connection from the pool, by
        # comparing their url.
        # If there's a match, then the adapter uses the connection from the
        # pool to make the new request.
        # Otherwise, a new connection is created and saved in the pool. If
        # there is no space in the pool, the new connection will replace the
        # least recently used one in the pool. The evicted connection will be
        # closed.
        #
        # The `pool_connections` argument indicates the maximum number of
        # connection saved in the pool, not the maximum number of open
        # connections allowed at the same time
        # (see https://urllib3.readthedocs.io/en/stable/advanced-usage.html).
        #
        # We set this value to be equal to micro-http's `MAX_CONNECTIONS` - 1.
        # This is because when reaching the `pool_connection` limit, it is not
        # guaranteed that the event to close the connection will be received
        # before the event that results in creating a new connection (this
        # depends on the kernel). In case the two events are not received in
        # the same order, or are received together, the server might try to add
        # a new connection before removing the old one, resulting in a
        # `SERVER_FULL_ERROR`.
        self.mount(DEFAULT_SCHEME, UnixAdapter(pool_connections=9))

        def is_good_response(response: int):
            """Return `True` for all HTTP 2xx response codes."""
            return 200 <= response < 300

        def is_status_ok(response: int):
            """Return `True` when HTTP response code is 200 OK."""
            return response == 200

        def is_status_no_content(response: int):
            """Return `True` when HTTP response code is 204 NoContent."""
            return response == 204

        def is_status_bad_request(response: int):
            """Return `True` when HTTP response code is 400 BadRequest."""
            return response == 400

        def is_status_not_found(response: int):
            """Return `True` when HTTP response code is 404 NotFound."""
            return response == 404

        def is_status_payload_too_large(response: int):
            """Return `True` when HTTP response code is 413 PayloadTooLarge."""
            return response == 413

        self.is_good_response = is_good_response
        self.is_status_ok = is_status_ok
        self.is_status_no_content = is_status_no_content
        self.is_status_bad_request = is_status_bad_request
        self.is_status_not_found = is_status_not_found
        self.is_status_payload_too_large = is_status_payload_too_large
