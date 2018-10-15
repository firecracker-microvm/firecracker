"""Wrapper over an http session with timed requests."""

import time

import requests_unixsocket

from framework.defs import API_USOCKET_NAME, MAX_API_CALL_DURATION_MS


class ApiTimeoutException(Exception):
    """A custom exception containing the details of the failed API call."""

    def __init__(self, duration, method, resource, payload):
        """Compose the error message from the API call components."""
        super(ApiTimeoutException, self).__init__(
            'API call exceeded maximum duration: {:.2f} ms.\n'
            'Call: {} {} {}'
            .format(duration, method, resource, payload)
        )


def timed_request(method):
    """Decorate functions to monitor their duration."""
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
                resource = args[1][args[1].find(
                    API_USOCKET_NAME)+len(API_USOCKET_NAME):]
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

    @timed_request
    def get(self, url, **kwargs):
        """Wrap the GET call with duration limit."""
        return super(Session, self).get(url, **kwargs)

    @timed_request
    def patch(self, url, data=None, **kwargs):
        """Wrap the PATCH call with duration limit."""
        return super(Session, self).patch(url, data=data, **kwargs)

    @timed_request
    def put(self, url, data=None, **kwargs):
        """Wrap the PUT call with duration limit."""
        return super(Session, self).put(url, data=data, **kwargs)
