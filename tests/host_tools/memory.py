# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for measuring memory utilization for a process."""
import asyncio

from subprocess import run, CalledProcessError, PIPE


MAX_MEMORY = 5 * 1024
MEMORY_COP_TIMEOUT = 1


def spawn_memory_monitor(mem_size_mib, pid):
    """Spawns a coroutine that monitors memory consumption of a process.

    If at some point the memory used exceeds mem_size_mib, an exception
    will be raised.

    Returns an asyncio.Future associated with the montioring coroutine
    """
    return asyncio.ensure_future(_memory_cop(mem_size_mib, pid))


async def _memory_cop(mem_size_mib, pid):
    """Coroutine for monitoring memory consumption of some pid.

    `pmap` is used to compute the memory overhead. If it exceeds
    the maximum value, the process exits immediately, failing any running
    test.
    """
    pmap_cmd = 'pmap -xq {}'.format(pid)
    while True:
        try:
            pmap_out = run(
                pmap_cmd,
                shell=True,
                check=True,
                stdout=PIPE
            ).stdout.decode('utf-8').split('\n')
        except CalledProcessError as e:
            print('Memory cop failed calling  \'{}\''.format(pmap_cmd))
            raise(e)

        if not pmap_out:
            # This should occur when Firecracker exited cleanly and
            # `pmap` isn't writing anything to `stdout` anymore.
            # However, in the current state of things, Firecracker
            # (at least sometimes) remains as a zombie, and `pmap`
            # always outputs, even though memory consumption is 0.
            return

        mem_total = sum([rss for rss in _pmap_rss_streamer(pmap_out, mem_size_mib)])
        if mem_total > MAX_MEMORY:
            raise MemoryError(
                'ERROR! Memory usage exceeded limit: {}/{} for pid: {}'.format(
                    mem_total, MAX_MEMORY, pid,
                )
            )

        await asyncio.sleep(MEMORY_COP_TIMEOUT)


def _pmap_rss_streamer(pmap_out, mem_size_mib):
    """Parses pmap output yielding RSS memory amounts
    """
    for line in pmap_out:
        tokens = line.split()
        try:
            total_size = int(tokens[1])
            rss = int(tokens[2])
        except ValueError:
            # This line doesn't contain memory related information.
            continue

        if total_size == mem_size_mib * 1024:
            # This is the guest's memory region.
            # TODO Check for the address of the guest's memory instead.
            continue

        yield rss
