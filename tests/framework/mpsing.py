# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A multi-process singleton implementation.

This module provides a facility for synchronization across a multi-process
pytest session, in the form of the `MultiprocessSingleton` class.

A `MultiprocessSingleton` object achieves cross-worker synchronization by
executing code in a single "server" process, under a lock. The process
where the singleton is initialized becomes the server process. Subsequently,
when called in the context of any child (i.e. "client") process, methods
marked with `@ipcmethod` are sent via an IPC pipe to the server process, for
execution. The result is returned to the caller via the same pipe.

`@ipcmethod` invokes are serialized via a lock, such that at any one time,
only one worker is executing code on its corresponding singleton server.

Restrictions:
  - the singleton server must be initialized before any workers are
    `fork()`ed;
  - `@ipcmethod` arguments and results must be picklable, since they are
    transmitted via an IPC pipe;
  - the server process must poll the singleton for incoming execution
    requests, and call its `handle_ipc_call()` method to handle them.
    The singleton provides a pollable file descriptor via its `fileno()`
    method.
"""

from multiprocessing import Pipe, Lock


def ipcmethod(fn):
    """Mark a singleton method to be executed in the server context.

    A multi-process singleton implementor should use this decorator to mark
    methods that should be executed in the server context, under the
    singleton lock.
    """
    def proxy_fn(inst, *args, **kwargs):
        # pylint: disable=protected-access
        return inst._ipc_call(fn.__name__, *args, **kwargs)
    proxy_fn.orig_fn = fn
    return proxy_fn


class SingletonReinitError(Exception):
    """Singleton reinitialization error."""


class MultiprocessSingleton:
    """A multi-process singleton (duh)."""

    _instance = None

    def __init__(self):
        """Docstring placeholder."""
        if self.__class__._instance is not None:
            raise SingletonReinitError()
        self._mpsing_lock = Lock()
        self._mpsing_server_conn, self._mpsing_client_conn = Pipe()

    @classmethod
    def instance(cls):
        """Return the local instance of this singleton."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ipc_call(self, fn_name, *args, **kwargs):
        """Peform the IPC call, from the client context.

        This method is called in the client context. It sends an RPC request
        to the server, and returns its result.
        """
        if not callable(getattr(self, fn_name)):
            raise TypeError(f"{fn_name} is not callable")
        with self._mpsing_lock:
            msg = (fn_name, args, kwargs)
            self._mpsing_client_conn.send(msg)
            result = self._mpsing_client_conn.recv()
        if isinstance(result, BaseException):
            # TODO: sending the exception through the IPC pipe will strip its
            #       __traceback__ property, as traceback objects cannot be
            #       pickled. It would be nice to send some kind of traceback
            #       info back though.
            raise result
        return result

    def fileno(self):
        """Return a pollable IPC file descriptor.

        The returned FD should be used to determine whether the server needs
        to service any pending requests (i.e. when data is ready to be read
        from the FD).
        """
        return self._mpsing_server_conn.fileno()

    def handle_ipc_call(self):
        """Handle the next IPC call from a client.

        Called only in the server context, this method will perform a blocking
        read from the IPC pipe. If the caller wants to avoid blocking here,
        they should poll/select `self.fileno()` for reading before calling
        this method.
        """
        (fn_name, args, kwargs) = self._mpsing_server_conn.recv()
        try:
            res = getattr(self, fn_name).orig_fn(self, *args, **kwargs)
        # pylint: disable=broad-except
        except BaseException as exc:
            res = exc
        self._mpsing_server_conn.send(res)
