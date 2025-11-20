# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A simple HTTP client for the Firecracker API"""

import urllib
from http import HTTPStatus

import requests
from requests_unixsocket import DEFAULT_SCHEME, UnixAdapter

from framework.swagger_validator import SwaggerValidator, ValidationError


class Session(requests.Session):
    """An HTTP over UNIX sockets Session

    Wrapper over requests_unixsocket.Session
    """

    def __init__(self):
        """Create a Session object."""
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


class Resource:
    """An abstraction over a REST path"""

    def __init__(self, api, resource, id_field=None):
        self._api = api
        self.resource = resource
        self.id_field = id_field

    def get(self):
        """Make a GET request"""
        url = self._api.endpoint + self.resource
        try:
            res = self._api.session.get(url)
        except Exception as e:
            if self._api.error_callback:
                self._api.error_callback("GET", self.resource, str(e))
            raise
        assert res.status_code == HTTPStatus.OK, res.json()

        # Validate response against Swagger specification
        # only validate successful requests
        if self._api.validator and res.status_code == HTTPStatus.OK:
            try:
                response_body = res.json()
                self._api.validator.validate_response(
                    "GET", self.resource, 200, response_body
                )
            except ValidationError as e:
                # Re-raise with more context
                raise ValidationError(
                    f"Response validation failed for GET {self.resource}: {e.message}"
                ) from e

        return res

    def request(self, method, path, **kwargs):
        """Make an HTTP request"""
        kwargs = {key: val for key, val in kwargs.items() if val is not None}
        url = self._api.endpoint + path
        try:
            res = self._api.session.request(method, url, json=kwargs)
        except Exception as e:
            if self._api.error_callback:
                self._api.error_callback(method, path, str(e))
            raise
        if res.status_code != HTTPStatus.NO_CONTENT:
            json = res.json()
            msg = res.content
            if "fault_message" in json:
                msg = json["fault_message"]
            elif "error" in json:
                msg = json["error"]
            raise RuntimeError(msg, json, res)

        # Validate request against Swagger specification
        # do this after the actual request as we only want to validate successful
        # requests as the tests may be trying to pass bad requests and assert an
        # error is raised.
        if self._api.validator:
            if kwargs:
                try:
                    self._api.validator.validate_request(method, path, kwargs)
                except ValidationError as e:
                    # Re-raise with more context
                    raise ValidationError(
                        f"Request validation failed for {method} {path}: {e.message}"
                    ) from e

            if res.status_code == HTTPStatus.OK:
                try:
                    response_body = res.json()
                    self._api.validator.validate_response(
                        method, path, 200, response_body
                    )
                except ValidationError as e:
                    # Re-raise with more context
                    raise ValidationError(
                        f"Response validation failed for {method} {path}: {e.message}"
                    ) from e
        return res

    def put(self, **kwargs):
        """Make a PUT request"""
        path = self.resource
        if self.id_field is not None:
            path += "/" + kwargs[self.id_field]
        return self.request("PUT", path, **kwargs)

    def patch(self, **kwargs):
        """Make a PATCH request"""
        path = self.resource
        if self.id_field is not None:
            path += "/" + kwargs[self.id_field]
        return self.request("PATCH", path, **kwargs)


class Api:
    """A simple HTTP client for the Firecracker API"""

    def __init__(self, api_usocket_full_name, *, validate=True, on_error=None):
        self.error_callback = on_error
        self.socket = api_usocket_full_name
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        self.endpoint = DEFAULT_SCHEME + url_encoded_path
        self.session = Session()

        # Initialize the swagger validator
        self.validator = SwaggerValidator() if validate else None

        self.describe = Resource(self, "/")
        self.vm = Resource(self, "/vm")
        self.vm_config = Resource(self, "/vm/config")
        self.actions = Resource(self, "/actions")
        self.boot = Resource(self, "/boot-source")
        self.drive = Resource(self, "/drives", "drive_id")
        self.version = Resource(self, "/version")
        self.logger = Resource(self, "/logger")
        self.machine_config = Resource(self, "/machine-config")
        self.metrics = Resource(self, "/metrics")
        self.network = Resource(self, "/network-interfaces", "iface_id")
        self.mmds = Resource(self, "/mmds")
        self.mmds_config = Resource(self, "/mmds/config")
        self.balloon = Resource(self, "/balloon")
        self.balloon_stats = Resource(self, "/balloon/statistics")
        self.vsock = Resource(self, "/vsock")
        self.snapshot_create = Resource(self, "/snapshot/create")
        self.snapshot_load = Resource(self, "/snapshot/load")
        self.cpu_config = Resource(self, "/cpu-config")
        self.entropy = Resource(self, "/entropy")
        self.pmem = Resource(self, "/pmem", "id")
        self.serial = Resource(self, "/serial")
        self.memory_hotplug = Resource(self, "/hotplug/memory")
