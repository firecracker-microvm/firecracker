# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generic utility functions that are used in the framework."""
import asyncio
import functools
import glob
import logging
import os
import re
import subprocess
import threading
import typing
from enum import Enum, auto
from collections import namedtuple, defaultdict
import psutil


CommandReturn = namedtuple("CommandReturn", "returncode stdout stderr")
CMDLOG = logging.getLogger("commands")


class ProcessCpuAffinity:
    """Manage process cpu affinity."""

    def __init__(self, pid):
        """Initialize CpuAffinity class."""
        self._pid = pid

    def get_threads(self) -> dict:
        """Return dict consisting of child threads."""
        threads_map = defaultdict(list)
        proc = psutil.Process(self._pid)
        for thread in proc.threads():
            threads_map[psutil.Process(thread.id).name()].append(thread.id)
        return threads_map

    def get_cpu_affinity(self) -> list:
        """Get CPU affinity for a thread."""
        return psutil.Process(self._pid).cpu_affinity()

    def set_cpu_affinity(self, cpulist: list) -> list:
        """Set CPU affinity for a thread."""
        real_cpulist = list(map(CpuMap, cpulist))
        return psutil.Process(self._pid).cpu_affinity(real_cpulist)


# pylint: disable=R0903
class CpuMap:
    """Cpu map from real cpu cores to containers visible cores.

    When a docker container is restricted in terms of assigned cpu cores,
    the information from `/proc/cpuinfo` will present all the cpu cores
    of the machine instead of showing only the container assigned cores.
    This class maps the real assigned host cpu cores to virtual cpu cores,
    starting from 0.
    """

    arr = []

    def __new__(cls, x):
        """Instantiate the class field."""
        if not CpuMap.arr:
            CpuMap.arr = CpuMap._cpus()
        return CpuMap.arr[x]

    @classmethod
    def _cpuset_mountpoint(cls):
        """Obtain the cpuset mountpoint."""
        cmd = "cat /proc/mounts | grep cgroup | grep cpuset | cut -d' ' -f2"
        _, stdout, _ = run_cmd(cmd)
        return stdout.strip()

    @classmethod
    def _cpus(cls):
        """Obtain the real processor map.

        See this issue for details:
        https://github.com/moby/moby/issues/20770.
        """
        cmd = "cat {}/cpuset.cpus".format(CpuMap._cpuset_mountpoint())
        _, cpulist, _ = run_cmd(cmd)
        return ListFormatParser(cpulist).parse()


class ListFormatParser:
    """Parser class for LIST FORMAT strings."""

    def __init__(self, content):
        """Initialize the parser with the content."""
        self._content = content.strip()

    @classmethod
    def _is_range(cls, rng):
        """Return true if the parser content is a range.

        E.g ranges: 0-10.
        """
        match = re.search("([0-9][1-9]*)-([0-9][1-9]*)", rng)
        # Group is a singular value.
        return match is not None

    @classmethod
    def _range_to_list(cls, rng):
        """Return a range of integers based on the content.

        The content respects the LIST FORMAT defined in the
        cpuset documentation.
        See: https://man7.org/linux/man-pages/man7/cpuset.7.html.
        """
        ends = rng.split("-")
        if len(ends) != 2:
            return []

        return list(range(int(ends[0]), int(ends[1]) + 1))

    def parse(self):
        """Parse list formats for cpuset and mems.

        See LIST FORMAT here:
        https://man7.org/linux/man-pages/man7/cpuset.7.html.
        """
        if len(self._content) == 0:
            return []

        groups = self._content.split(",")
        arr = set()

        def func(acc, cpu):
            if ListFormatParser._is_range(cpu):
                acc.update(ListFormatParser._range_to_list(cpu))
            else:
                acc.add(int(cpu))
            return acc

        return list(functools.reduce(func, groups, arr))


class StoppableThread(threading.Thread):
    """
    Thread class with a stop() method.

    The thread itself has to check regularly for the stopped() condition.
    """

    def __init__(self, *args, **kwargs):
        """Set up a Stoppable thread."""
        super().__init__(*args, **kwargs)
        self._should_stop = False

    def stop(self):
        """Set that the thread should stop."""
        self._should_stop = True

    def stopped(self):
        """Check if the thread was stopped."""
        return self._should_stop


class CpuVendor(Enum):
    """CPU vendors enum."""

    AMD = auto()
    INTEL = auto()


def get_cpu_vendor():
    """Return the CPU vendor."""
    brand_str = subprocess.check_output("lscpu", shell=True).strip().decode()
    if 'AuthenticAMD' in brand_str:
        return CpuVendor.AMD
    return CpuVendor.INTEL


def search_output_from_cmd(cmd: str,
                           find_regex: typing.Pattern) -> typing.Match:
    """
    Run a shell command and search a given regex object in stdout.

    If the regex object is not found, a RuntimeError exception is raised.

    :param cmd: command to run
    :param find_regex: regular expression object to search for
    :return: result of re.search()
    """
    # Run the given command in a shell
    _, stdout, _ = run_cmd(cmd)

    # Search for the object
    content = re.search(find_regex, stdout)

    # If the result is not None, return it
    if content:
        return content

    raise RuntimeError("Could not find '%s' in output for '%s'" %
                       (find_regex.pattern, cmd))


def get_files_from(find_path: str, pattern: str, exclude_names: list = None,
                   recursive: bool = True):
    """
    Return a list of files from a given path, recursively.

    :param find_path: path where to look for files
    :param pattern: what pattern to apply to file names
    :param exclude_names: folder names to exclude
    :param recursive: do a recursive search for the given pattern
    :return: list of found files
    """
    found = []

    # For each directory in the given path
    for path_dir in os.scandir(find_path):
        # Check if it should be skipped
        if path_dir.name in exclude_names or os.path.isfile(path_dir):
            continue

        # Run glob inside the folder with the given pattern
        found.extend(
            glob.glob(f"{find_path}/{path_dir.name}/**/{pattern}",
                      recursive=recursive))

    return found


async def run_cmd_async(cmd, ignore_return_code=False, no_shell=False):
    """
    Create a coroutine that executes a given command.

    :param cmd: command to execute
    :param ignore_return_code: whether a non-zero return code should be ignored
    :param noshell: don't run the command in a sub-shell
    :return: return code, stdout, stderr
    """
    if isinstance(cmd, list) or no_shell:
        # Create the async process
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
    else:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

    # Capture stdout/stderr
    stdout, stderr = await proc.communicate()

    output_message = f"\n[{proc.pid}] Command:\n{cmd}"
    # Append stdout/stderr to the output message
    if stdout.decode() != "":
        output_message += f"\n[{proc.pid}] stdout:\n{stdout.decode()}"
    if stderr.decode() != "":
        output_message += f"\n[{proc.pid}] stderr:\n{stderr.decode()}"

    # If a non-zero return code was thrown, raise an exception
    if not ignore_return_code and proc.returncode != 0:
        output_message += \
            f"\nReturned error code: {proc.returncode}"

        if stderr.decode() != "":
            output_message += \
                f"\nstderr:\n{stderr.decode()}"
        raise ChildProcessError(output_message)

    # Log the message with one call so that multiple statuses
    # don't get mixed up
    CMDLOG.debug(output_message)

    return CommandReturn(
        proc.returncode,
        stdout.decode(),
        stderr.decode())


def run_cmd_list_async(cmd_list):
    """
    Run a list of commands asynchronously and wait for them to finish.

    :param cmd_list: list of commands to execute
    :return: None
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # Create event loop when one is not available
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    cmds = []
    # Create a list of partial functions to run
    for cmd in cmd_list:
        cmds.append(run_cmd_async(cmd))

    # Wait until all are complete
    loop.run_until_complete(
        asyncio.gather(
            *cmds
        )
    )


def run_cmd(cmd, ignore_return_code=False, no_shell=False):
    """
    Run a command using the async function that logs the output.

    :param cmd: command to run
    :param ignore_return_code: whether a non-zero return code should be ignored
    :param noshell: don't run the command in a sub-shell
    :returns: tuple of (return code, stdout, stderr)
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # Create event loop when one is not available
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(
        run_cmd_async(cmd=cmd,
                      ignore_return_code=ignore_return_code,
                      no_shell=no_shell))


def eager_map(func, iterable):
    """Map version for Python 3.x which is eager and returns nothing."""
    for _ in map(func, iterable):
        continue
