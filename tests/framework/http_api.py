# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A simple HTTP client for the Firecracker API"""

# pylint:disable=too-few-public-methods

import urllib
from http import HTTPStatus

import requests
from requests_unixsocket import DEFAULT_SCHEME, UnixAdapter


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
        res = self._api.session.get(url)
        assert res.status_code == HTTPStatus.OK, res.json()
        return res

    def request(self, method, path, **kwargs):
        """Make an HTTP request"""
        kwargs = {key: val for key, val in kwargs.items() if val is not None}
        url = self._api.endpoint + path
        res = self._api.session.request(method, url, json=kwargs)
        if res.status_code != HTTPStatus.NO_CONTENT:
            json = res.json()
            msg = res.content
            if "fault_message" in json:
                msg = json["fault_message"]
            elif "error" in json:
                msg = json["error"]
            raise RuntimeError(msg, json, res)
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

    def __init__(self, api_usocket_full_name):
        self.socket = api_usocket_full_name
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        self.endpoint = DEFAULT_SCHEME + url_encoded_path
        self.session = Session()

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
        self.hotplug = Resource(self, "/hotplug")
