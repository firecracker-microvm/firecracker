# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the jailer's behavior."""
import os
import stat
import subprocess

from framework.defs import FC_BINARY_NAME
from framework.jailer import JailerContext
import host_tools.cargo_build as build_tools


# These are the permissions that all files/dirs inside the jailer have.
REG_PERMS = stat.S_IRUSR | stat.S_IWUSR | \
    stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | \
    stat.S_IROTH | stat.S_IXOTH
DIR_STATS = stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
FILE_STATS = stat.S_IFREG | REG_PERMS
SOCK_STATS = stat.S_IFSOCK | REG_PERMS
# These are the stats of the devices created by tha jailer.
CHAR_STATS = stat.S_IFCHR | stat.S_IRUSR | stat.S_IWUSR


def check_stats(filepath, stats, uid, gid):
    """Assert on uid, gid and expected stats for the given path."""
    st = os.stat(filepath)

    assert st.st_gid == gid
    assert st.st_uid == uid
    assert st.st_mode ^ stats == 0


def test_default_chroot(test_microvm_with_ssh):
    """
    Test that the jailer assigns a default chroot if none is specified.

    @type: security
    """
    test_microvm = test_microvm_with_ssh

    # Start customizing arguments.
    # Test that firecracker's default chroot folder is indeed `/srv/jailer`.
    test_microvm.jailer.chroot_base = None

    test_microvm.spawn()

    # Test the expected outcome.
    assert os.path.exists(test_microvm.jailer.api_socket_path())


def test_empty_jailer_id(test_microvm_with_ssh):
    """
    Test that the jailer ID cannot be empty.

    @type: security
    """
    test_microvm = test_microvm_with_ssh
    fc_binary, _ = build_tools.get_firecracker_binaries()

    # Set the jailer ID to None.
    test_microvm.jailer = JailerContext(
        jailer_id="",
        exec_file=fc_binary,
    )

    # pylint: disable=W0703
    try:
        test_microvm.spawn()
        # If the exception is not thrown, it means that Firecracker was
        # started successfully, hence there's a bug in the code due to which
        # we can set an empty ID.
        assert False
    except Exception as err:
        expected_err = "Jailer error: Invalid instance ID: invalid len (0);" \
                       "  the length must be between 1 and 64"
        assert expected_err in str(err)


def test_default_chroot_hierarchy(test_microvm_with_initrd):
    """
    Test the folder hierarchy created by default by the jailer.

    @type: security
    """
    test_microvm = test_microvm_with_initrd

    test_microvm.spawn()

    # We do checks for all the things inside the chroot that the jailer crates
    # by default.
    check_stats(test_microvm.jailer.chroot_path(), DIR_STATS,
                test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev"),
                DIR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev/net"),
                DIR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "run"),
                DIR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev/net/tun"),
                CHAR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev/kvm"),
                CHAR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(),
                             "firecracker"), FILE_STATS, 0, 0)


def test_arbitrary_usocket_location(test_microvm_with_initrd):
    """
    Test arbitrary location scenario for the api socket.

    @type: security
    """
    test_microvm = test_microvm_with_initrd
    test_microvm.jailer.extra_args = {'api-sock': 'api.socket'}

    test_microvm.spawn()

    check_stats(os.path.join(test_microvm.jailer.chroot_path(),
                             "api.socket"), SOCK_STATS,
                test_microvm.jailer.uid, test_microvm.jailer.gid)


def check_cgroups(cgroups, cgroup_location, jailer_id):
    """Assert that every cgroup in cgroups is correctly set."""
    for cgroup in cgroups:
        controller = cgroup.split('.')[0]
        file_name, value = cgroup.split('=')
        location = cgroup_location + '/{}/{}/{}/'.format(
            controller,
            FC_BINARY_NAME,
            jailer_id
        )
        tasks_file = location + 'tasks'
        file = location + file_name

        assert open(file, 'r').readline().strip() == value
        assert open(tasks_file, 'r').readline().strip().isdigit()


def get_cpus(node):
    """Retrieve CPUs from NUMA node."""
    sys_node = '/sys/devices/system/node/node' + str(node)
    assert os.path.isdir(sys_node)
    node_cpus_path = sys_node + '/cpulist'

    return open(node_cpus_path, 'r').readline().strip()


def test_cgroups(test_microvm_with_initrd):
    """
    Test the cgroups are correctly set by the jailer.

    @type: security
    """
    test_microvm = test_microvm_with_initrd
    test_microvm.jailer.cgroups = ['cpu.shares=2', 'cpu.cfs_period_us=200000']
    test_microvm.jailer.numa_node = 0

    test_microvm.spawn()

    # Retrieve CPUs from NUMA node 0.
    node_cpus = get_cpus(test_microvm.jailer.numa_node)

    # Apending the cgroups that should be creating by --node option
    # This must be changed once --node options is removed
    cgroups = test_microvm.jailer.cgroups + [
        'cpuset.mems=0',
        'cpuset.cpus={}'.format(node_cpus)
    ]

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = '/sys/fs/cgroup'
    assert os.path.isdir(sys_cgroup)

    check_cgroups(cgroups, sys_cgroup, test_microvm.jailer.jailer_id)


def test_node_cgroups(test_microvm_with_initrd):
    """
    Test the --node cgroups are correctly set by the jailer.

    @type: security
    """
    test_microvm = test_microvm_with_initrd
    test_microvm.jailer.cgroups = None
    test_microvm.jailer.numa_node = 0

    test_microvm.spawn()

    # Retrieve CPUs from NUMA node 0.
    node_cpus = get_cpus(test_microvm.jailer.numa_node)

    # Apending the cgroups that should be creating by --node option
    # This must be changed once --node options is removed
    cgroups = [
        'cpuset.mems=0',
        'cpuset.cpus={}'.format(node_cpus)
    ]

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = '/sys/fs/cgroup'
    assert os.path.isdir(sys_cgroup)

    check_cgroups(cgroups, sys_cgroup, test_microvm.jailer.jailer_id)


def test_cgroups_without_numa(test_microvm_with_initrd):
    """
    Test the cgroups are correctly set by the jailer, without numa assignment.

    @type: security
    """
    test_microvm = test_microvm_with_initrd
    test_microvm.jailer.cgroups = ['cpu.shares=2', 'cpu.cfs_period_us=200000']

    test_microvm.spawn()

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = '/sys/fs/cgroup'
    assert os.path.isdir(sys_cgroup)

    check_cgroups(
        test_microvm.jailer.cgroups,
        sys_cgroup,
        test_microvm.jailer.jailer_id
    )


def test_new_pid_namespace(test_microvm_with_ssh):
    """
    Test that Firecracker is spawned in a new PID namespace if requested.

    @type: security
    """
    test_microvm = test_microvm_with_ssh

    test_microvm.jailer.daemonize = False
    test_microvm.jailer.new_pid_ns = True

    test_microvm.spawn()

    # Check that the PID file exists.
    fc_pid = test_microvm.pid_in_new_ns
    assert fc_pid is not None

    # Validate the PID.
    stdout = subprocess.check_output("pidof firecracker", shell=True)
    assert str(fc_pid) in stdout.strip().decode()

    # Get the thread group IDs in each of the PID namespaces of which
    # Firecracker process is a member of.
    nstgid_cmd = "cat /proc/{}/status | grep NStgid".format(fc_pid)
    nstgid_list = subprocess.check_output(
        nstgid_cmd,
        shell=True
    ).decode('utf-8').strip().split("\t")[1:]

    # Check that Firecracker's PID namespace is nested. `NStgid` should
    # report two values and the last one should be 1, because Firecracker
    # becomes the init(1) process of the new PID namespace it is spawned in.
    assert len(nstgid_list) == 2
    assert int(nstgid_list[1]) == 1
    assert int(nstgid_list[0]) == fc_pid
