# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generic utility functions that are used in the framework."""
import asyncio
import glob
import os
import re
import subprocess
import threading
import typing


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
    out = subprocess.run(cmd, shell=True, check=True,
                         stdout=subprocess.PIPE).stdout.decode("utf-8")

    # Search for the object
    content = re.search(find_regex, out)

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


async def run_cmd_async(cmd):
    """
    Create a coroutine that executes a given command.

    :param cmd: command to execute
    :return: stdout, stderr
    """
    # Create the async process
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    # Capture stdin/stdout
    stdout, stderr = await proc.communicate()

    output_message = f"\n[{proc.pid}] Command:\n{cmd}"
    # Append stdout/stderr to the output message
    if stdout.decode() != "":
        output_message += f"\n[{proc.pid}] stdout:\n{stdout.decode()}"
    if stderr.decode() != "":
        output_message += f"\n[{proc.pid}] stderr:\n{stderr.decode()}"

    # If a non-zero return code was thrown, raise an exception
    if proc.returncode != 0:
        output_message += \
            f"\nReturned error code: {proc.returncode}"

        if stderr.decode() != "":
            output_message += \
                f"\nstderr:\n{stderr.decode()}"
        raise ChildProcessError(output_message)

    # Print the message with one call so that multiple statuses
    # don't get mixed up
    print(output_message)

    return stdout.decode(), stderr.decode()


def run_cmd(cmd):
    """
    Run a command using the async function that logs the output.

    :param cmd: command to run
    :returns: tuple of (stdout, stderr)
    """
    return asyncio.get_event_loop().run_until_complete(
        run_cmd_async(cmd))


def run_cmd_list_async(cmd_list):
    """
    Run a list of commands asynchronously and wait for them to finish.

    :param cmd_list: list of commands to execute
    :return: None
    """
    loop = asyncio.get_event_loop()

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


class StoppableThread(threading.Thread):
    """
    Thread class with a stop() method.

    The thread itself has to check regularly for the stopped() condition.
    """

    def __init__(self, *args, **kwargs):
        """Set up a Stoppable thread."""
        super(StoppableThread, self).__init__(*args, **kwargs)
        self._should_stop = False

    def stop(self):
        """Set that the thread should stop."""
        self._should_stop = True

    def stopped(self):
        """Check if the thread was stopped."""
        return self._should_stop
