#!/usr/bin/env python3

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""This script is intended to be an entry point for `devtool test`.

It provides the needed primitives for creation of a "shielded" environment.
Shielding is based entirely on cgroup cpuset. The idea behind the environment
setup is to isolate and shield workloads started by the testing framework. To
this end, we will be interested in three high-level cpusets:
* root - the root cpuset hierarchy.
* system - where existing tasks will run.
* docker - where tests workloads will run.

Docker shares all the available cpus and memory nodes with root, but when
containers start, they can receive a slice of the available cpus and memory,
depending on what is requested by the "caller". The slice must be contained by
an isolated NUMA node. Shielding this slice of the NUMA node is done by moving
all the existing tasks inside system cpuset, letting the "shielded" and free
slice available for a new docker container.
"""


import os
import re
import io
import functools
import random
import sys
from enum import IntEnum
import tools.log_utils as log


class ExitCode(IntEnum):
    """Exit codes used across the script."""

    OKSUCCESS = 0
    EINVPATTERN = 1
    EINVSYSFS = 2
    ENOAVAILCPU = 3
    ECONFLICTCPUSET = 4
    EINVARG = 5
    ENOAVAILMEM = 6
    EOFFNODE = 7
    EDIRTYENV = 8
    ESHARENODE = 9
    ETEARDOWN = 10
    EEXCEPT = 11
    ESKIP = 12
    ESINGLENUMANODE = 13
    ERANGEPARSE = 14


# Patterns.
RANGE_PATTERN = "([0-9][1-9]*)-([0-9][1-9]*)"


# Hardcoded sysfs information.
SYSFS_MOUNTPOINT = "/host_sys"
CPUSET_MOUNTPOINT = "/host_cpuset"


def _is_range(content):
    """Return true if `content` is a range.

    Args:
        * content (str).
    Returns:
        * boolean: True if `content` is a range and False otherwise.
    """
    match = re.search(RANGE_PATTERN, content)
    # group is a singular value.
    return match is not None


def _range(content):
    """Return a range of integers based on the `content`.

    The `content` respects the LIST FORMAT defined in the
    cpuset documentation.
    See: https://man7.org/linux/man-pages/man7/cpuset.7.html.

    Args:
        * content (str).
    Returns:
        * list of ints: a list with ints corresponding to a range
                        of CPU cores IDs.
    """
    content = content.strip()
    ends = content.split("-")
    if len(ends) != 2:
        log.die("Range parse error.")
        sys.exit(ExitCode.ERANGEPARSE)
    return list(range(int(ends[0]), int(ends[1]) + 1))


def _parse_list_format(content):
    """Parse list formats for cpuset and mems.

    See LIST FORMAT here: https://man7.org/linux/man-pages/man7/cpuset.7.html.

    Args:
        * content (str).
    Returns:
        * list of ints: ints corresponding to elements of a LIST FORMAT, as
                        described into `cpuset` documentation.
    """
    content = content.strip()
    if len(content) == 0:
        return []

    groups = content.split(",")
    arr = set()

    def func(acc, cpu):
        if _is_range(cpu):
            acc.update(_range(cpu))
        else:
            acc.add(int(cpu))
        return acc

    return list(functools.reduce(func, groups, arr))


def _is_node_online(numa_node_id):
    """Check whether a NUMA node is online.

    Args:
        * numa_node_id (int).
    Returns:
        * boolean.
    """
    online_numa_nodes_path = SYSFS_MOUNTPOINT + "/devices/system/node/online"
    with open(online_numa_nodes_path) as fp:
        content = fp.readline()
        online_numa_nodes = _parse_list_format(content)
        return len(list(filter(lambda cpu: cpu == numa_node_id,
                               online_numa_nodes))) > 0


def _get_cpulist(numa_node_id, raw=False):
    """Get the cpulist of a NUMA node.

    Args:
        * numa_node_id (int).
        * raw (boolean): Default is False. If set to True, will return
                         the content found in the cpulist information
                         present in sysfs.
     Returns:
        * str: the content found in the NUMA node cpulist file.
        * list of ints: ints corresponding to elements of a LIST FORMAT, as
                        described into `cpuset` documentation.
    """
    cpulist_path = SYSFS_MOUNTPOINT + "/devices/system/node/node{}/cpulist"\
        .format(numa_node_id)
    with open(cpulist_path) as fp:
        if raw:
            return fp.readline().strip()
        return _parse_list_format(fp.readline())


def _is_memory_node_available(numa_node_id):
    """Check if the memory node is used by an explicit cpuset.

    By explicit cpusets we mean cpusets different than root and '/docker'

    Args:
        * numa_node_id (int).
    Returns:
        * boolean.
    """
    (root, dirnames, _) = next(os.walk(CPUSET_MOUNTPOINT))
    for dirname in dirnames:
        if dirname == "docker":
            continue

        with open(root + "/" + dirname + "/cpuset.mems") as fp:
            log.say(root + "/" + dirname + "/cpuset.mems")
            mems = _parse_list_format(fp.readline())
            if not len(list(filter(lambda m: m == numa_node_id, mems))) == 0:
                return False

    return True


def _get_unavailable_cpus():
    """Return a set unavailable CPU cores.

    An unavailable CPU core is a cpu id which is used by
    others cpuset than `/` (root) and `/docker`.

    Returns:
        * list of ints: a list of CPU core IDs used by other cpusets than `/`
                        (root) and `/docker`.
    """
    (root, dirnames, _) = next(os.walk(CPUSET_MOUNTPOINT))
    unavail_cpus = set()
    for dirname in dirnames:
        if dirname == "docker":
            continue

        with open(root + "/" + dirname + "/cpuset.cpus") as fp:
            unavail_cpus |= set(_parse_list_format(fp.readline()))

    return list(unavail_cpus)


def _get_available_cpus(numa_node_id):
    """Determine NUMA node CPUs which are not assigned to an explicit cpuset.

    By explicit cpusets we mean cpusets different than root and '/docker'.

    Args:
        * numa_node_id (int).
    Returns:
        * list of ints: a list of CPU core IDs free for use by docker
                        containers.
    """
    cpulist = _get_cpulist(numa_node_id)
    unavail_cpus = _get_unavailable_cpus()
    avail_cpus = [cpu for cpu in cpulist if cpu not in unavail_cpus]
    return avail_cpus


def validate(shield):
    """Validate that the shield pattern is respected.

    It also validates that the shield pattern can be satisfied.
    Exit if the shield is not valid. Shield pattern:
    {NUMA_NODE_ID};{CPUS_COUNT}.

    Args:
        * shield (str): Respects the shield pattern.
    """
    match = re.search("^(0|[1-9][0-9]*);([1-9][0-9]*)$", shield)
    if match is None:
        log.die("Invalid shield: '{}'. Please stick with the pattern:"
                " '{{NUMA_NODE_ID}};{{CPUS_COUNT}}'.".format(shield),
                ExitCode.EINVPATTERN)

    numa_node_id = int(match.group(1))
    cpus_count = int(match.group(2))
    if not _is_node_online(numa_node_id):
        log.die("NUMA node {} is not online.".format(numa_node_id),
                ExitCode.EOFFNODE)

    if len(_get_available_cpus(numa_node_id)) < cpus_count:
        log.die("Can not provide {} CPUs for NUMA node {}."
                .format(cpus_count, numa_node_id), ExitCode.ENOAVAILCPU)

    if not _is_memory_node_available(numa_node_id):
        log.die("NUMA node {} memory is assigned to an existing cpuset,"
                " other than '/' and 'docker'.".format(numa_node_id),
                ExitCode.ENOAVAILMEM)


def ensure_environment(numa_node_id, cpus_count, return_to_stdout=False):
    """Exit if NUMA node id or cpus count CPU cores are not free.

    It verifies if the environment can be satisfied by using the
    specified numa node id and cpus count of the same numa node.
    Exits if it can not produce a list of cpus count CPU cores, of the
    numa node id.

    Args:
        * numa_node_id (positive int).
        * cpus_count (positive int).
        * return_to_stdout (boolean): False by default. If set to True,
        it changes the format of the return type.

    Returns:
        * list: A list of positive ints with all the CPUs cores that can
                be used to set up an isolated enviornment for numa node id,
                which is not used by other cpusets.
        * str: Returns a cpuset list formatted set of CPUs cores which can be
               written directly into the `cpuset.cpus` file of a cpuset.
    """
    if numa_node_id < 0:
        log.die("Invalid NUMA node id: {}.".format(numa_node_id),
                ExitCode.EINVARG)

    if cpus_count < 1:
        log.die("Invalid cpus count: {}.".format(cpus_count), ExitCode.EINVARG)

    if not _is_node_online(numa_node_id):
        log.die("NUMA node is not online: {}.".format(numa_node_id),
                ExitCode.EOFFNODE)

    if not _is_memory_node_available(numa_node_id):
        log.die("NUMA node {} memory is assigned to other cpuset."
                .format(numa_node_id), ExitCode.ENOAVAILMEM)

    cpu_list = _get_cpulist(numa_node_id)
    avail_cpus = _get_available_cpus(numa_node_id)

    cpu_list_len = functools.reduce(lambda acc, cpu: acc + cpu, cpu_list, 0)

    if cpu_list_len < cpus_count or len(avail_cpus) < cpus_count:
        log.die("Can not provide {} CPUs for NUMA node {}.".
                format(cpus_count, numa_node_id), ExitCode.ENOAVAILCPU)

    if return_to_stdout:
        return ','.join(map(str, avail_cpus))

    return avail_cpus


def create_system_cpuset(excluded_numa_node_id):
    """Create a 'system' cpuset based on resources which can not be used.

    Chooses the first found online numa node that can be used and bound its
    resources to the 'system' cpuset.

    Args:
        excluded_numa_node_id (positive int).
    """
    cpuset_system_path = CPUSET_MOUNTPOINT + "/system"
    system_exists = os.path.isdir(cpuset_system_path)
    if system_exists:
        log.say_warn("'system' cpuset already exists.")
        sys.exit(ExitCode.ESKIP)

    online_numa_nodes_path = SYSFS_MOUNTPOINT + "/devices/system/node/online"
    with open(online_numa_nodes_path) as fp:
        online_numa_nodes = _parse_list_format(fp.readline())
        avail_nodes = list(filter(lambda node: node != excluded_numa_node_id,
                                  online_numa_nodes))
        if len(avail_nodes) == 0:
            log.say_warn("There is a single NUMA node on the system, where"
                         " tests can run. Skipping creation of the system"
                         " tasks cpuset...")
            sys.exit(ExitCode.ESINGLENUMANODE)

    # Create a 'system' cpuset if only there is a separate NUMA node which
    # can host it.
    system_node = random.choice(avail_nodes)
    try:
        os.mkdir(cpuset_system_path)
    except IOError as err:
        if str(err).find("Permission denied") != -1:
            log.die("Please run as a privileged user if you want to create"
                    " 'system' cpuset.", ExitCode.EEXCEPT)
        else:
            log.die(str(err), ExitCode.EEXCEPT)

    # Impose the isolation for the entire CPULIST of the system node.
    with open(cpuset_system_path + "/cpuset.cpus", "r+") as fp:
        fp.write(_get_cpulist(system_node, raw=True))

    with open(cpuset_system_path + "/cpuset.mems", "r+") as fp:
        fp.write(str(system_node))

    # Move root existing tasks to "system" cpuset.
    with open(CPUSET_MOUNTPOINT + "/tasks", "r+") as root_tasks:
        pids = root_tasks.readlines()

        def move_pid(pid):
            try:
                system_tasks = io.open(cpuset_system_path + "/tasks",
                                       'w', encoding="iso8859-1")
                system_tasks.write(pid)
                system_tasks.close()
                return None
            except IOError:
                return pid

        unmovable = list(filter(lambda pid: pid is not None,
                                map(move_pid, pids)))
        if len(unmovable) != 0:
            log.say("Unmovable tasks: {}.".format(len(unmovable)))

        log.say("'system' cpuset was succesfully created.")


def teardown_system_cpuset():
    """Delete a cpuset called 'system'.

    Before deleting the 'system' cpuset, all the tasks bound to the cpuset are
    moved to '/' (root) cpuset.
    """
    cpuset_system_path = CPUSET_MOUNTPOINT + "/system"

    dir_exists = os.path.isdir(cpuset_system_path)
    if not dir_exists:
        log.say_warn("System tasks cpuset does not exist.")
        sys.exit(ExitCode.OKSUCCESS)

    # Move existing tasks to "root" cpuset.
    with open(cpuset_system_path + "/tasks") as system_tasks:
        pids = system_tasks.readlines()
        for pid in pids:
            try:
                root_tasks = io.open(CPUSET_MOUNTPOINT + "/tasks", 'w',
                                     encoding="iso8859-1")
                root_tasks.write(pid)
                root_tasks.close()
            except IOError as err:
                # Warn unknown exception. It is not fatal.
                log.say_warn(str(err))

    try:
        os.rmdir(cpuset_system_path)
    except IOError as err:
        if str(err).find("Device or resource busy"):
            log.die(str(err), ExitCode.EEXCEPT)
        else:
            log.say_warn(str(err))

    dir_exists = os.path.isdir(cpuset_system_path)
    if dir_exists:
        log.die("'system' cpuset could not be removed.", ExitCode.ETEARDOWN)

    log.say("'system' cpuset was succesfully removed.")
