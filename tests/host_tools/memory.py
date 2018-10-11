"""Utilities for measuring memory utilization for a process."""
import time

from subprocess import run, PIPE
from threading import Thread


MAX_MEMORY = 5 * 1024
MEMORY_COP_TIMEOUT = 1


def threaded_memory_monitor(mem_size_mib, pid):
    """Spawns a thread that monitors memory consumption of a process.

    If at some point the memory used exceeds mem_size_mib, the calling thread
    will trigger error.
    """
    memory_cop_thread = Thread(target=_memory_cop, args=(
        mem_size_mib,
        pid
    ))
    memory_cop_thread.start()


def _memory_cop(mem_size_mib, pid):
    """Thread for monitoring memory consumption of some pid.

    `pmap` is used to compute the memory overhead. If it exceeds
    the maximum value, the process exits immediately, failing any running
    test.
    """
    pmap_cmd = 'pmap -xq {}'.format(pid)
    while True:
        mem_total = 0
        pmap_out = run(
            pmap_cmd,
            shell=True,
            check=True,
            stdout=PIPE
        ).stdout.decode('utf-8').split('\n')
        for line in pmap_out:
            tokens = line.split()
            if not tokens:
                # This should occur when Firecracker exited cleanly and
                # `pmap` isn't writing anything to `stdout` anymore.
                # However, in the current state of things, Firecracker
                # (at least sometimes) remains as a zombie, and `pmap`
                # always outputs, even though memory consumption is 0.
                break
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
            mem_total += rss

        if mem_total > MAX_MEMORY:
            print('ERROR! Memory usage exceeded limit: {}'
                  .format(mem_total))
            exit(-1)

        if not mem_total:
            # Until we have a reliable way to a) kill Firecracker, b) know
            # Firecracker is dead, this will have to do.
            return

        time.sleep(MEMORY_COP_TIMEOUT)
