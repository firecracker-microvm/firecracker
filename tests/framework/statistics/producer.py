# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Producer of statistics."""

from abc import ABC, abstractmethod
from typing import Callable, Any
import types
from framework import utils


# pylint: disable=R0903
class Producer(ABC):
    """Base class for raw results producer."""

    @abstractmethod
    def produce(self) -> Any:
        """Produce raw results."""


class SSHCommand(Producer):
    """Producer from executing ssh commands."""

    def __init__(self, cmd, ssh_connection):
        """Initialize the raw data producer."""
        self._cmd = cmd
        self._ssh_connection = ssh_connection

    def produce(self) -> Any:
        """Return the output of the executed ssh command."""
        rc, stdout, stderr = \
            self._ssh_connection.execute_command(self._cmd)
        assert rc == 0
        assert stderr.read() == ""

        return stdout.read()

    @property
    def ssh_connection(self):
        """Return the ssh connection used by the producer.

        The ssh connection used by the producer to execute commands on
        the guest.
        """
        return self._ssh_connection

    @ssh_connection.setter
    def ssh_connection(self, ssh_connection):
        """Set the ssh connection used by the producer."""
        self._ssh_connection = ssh_connection

    @property
    def cmd(self):
        """Return the command executed on guest."""
        return self._cmd

    @cmd.setter
    def cmd(self, cmd):
        """Set the command executed on guest."""
        self._cmd = cmd


class HostCommand(Producer):
    """Producer from executing commands on host."""

    def __init__(self, cmd):
        """Initialize the raw data producer."""
        self._cmd = cmd

    def produce(self) -> Any:
        """Return output of the executed command."""
        result = utils.run_cmd(self._cmd)
        return result.stdout

    @property
    def cmd(self):
        """Return the command executed on host."""
        return self._cmd

    @cmd.setter
    def cmd(self, cmd):
        """Set the command executed on host."""
        self._cmd = cmd


class LambdaProducer(Producer):
    """Producer from calling python functions."""

    def __init__(self, func, func_kwargs=None):
        """Initialize the raw data producer."""
        assert callable(func)
        self._func = func
        self._func_kwargs = func_kwargs

    # pylint: disable=R1710
    def produce(self) -> Any:
        """Call `self._func`."""
        if self._func_kwargs:
            raw_data = self._func(**self._func_kwargs)
            if isinstance(raw_data, types.GeneratorType):
                for res in raw_data:
                    yield res
            else:
                return raw_data
        else:
            raw_data = self._func()
            if isinstance(raw_data, types.GeneratorType):
                for res in raw_data:
                    yield res
            else:
                return raw_data

    @property
    def func(self):
        """Return producer function."""
        return self._func

    @func.setter
    def func(self, func: Callable):
        self._func = func

    @property
    def func_kwargs(self):
        """Return producer function arguments."""
        return self._func_kwargs

    @func_kwargs.setter
    def func_kwargs(self, func_kwargs):
        self._func_kwargs = func_kwargs
