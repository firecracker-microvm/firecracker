# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the jailer's behavior."""

# pylint: disable=redefined-outer-name

import functools
import http.client as http_client
import os
import resource
import stat
import subprocess
import time

import psutil
import pytest
import requests
import urllib3

import host_tools.cargo_build as build_tools
from framework.defs import FC_BINARY_NAME
from framework.jailer import JailerContext

# These are the permissions that all files/dirs inside the jailer have.
REG_PERMS = (
    stat.S_IRUSR
    | stat.S_IWUSR
    | stat.S_IXUSR
    | stat.S_IRGRP
    | stat.S_IXGRP
    | stat.S_IROTH
    | stat.S_IXOTH
)
DIR_STATS = stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
FILE_STATS = stat.S_IFREG | REG_PERMS
SOCK_STATS = stat.S_IFSOCK | REG_PERMS
# These are the stats of the devices created by tha jailer.
CHAR_STATS = stat.S_IFCHR | stat.S_IRUSR | stat.S_IWUSR
# Limit on file size in bytes.
FSIZE = 2097151
# Limit on number of file descriptors.
NOFILE = 1024
# Resource limits to be set by the jailer.
RESOURCE_LIMITS = [
    "no-file={}".format(NOFILE),
    "fsize={}".format(FSIZE),
]


def check_stats(filepath, stats, uid, gid):
    """Assert on uid, gid and expected stats for the given path."""
    st = os.stat(filepath)

    assert st.st_gid == gid
    assert st.st_uid == uid
    assert st.st_mode ^ stats == 0


def test_default_chroot(test_microvm_with_api):
    """
    Test that the jailer assigns a default chroot if none is specified.
    """
    test_microvm = test_microvm_with_api

    # Start customizing arguments.
    # Test that firecracker's default chroot folder is indeed `/srv/jailer`.
    test_microvm.jailer.chroot_base = None

    test_microvm.spawn()

    # Test the expected outcome.
    assert os.path.exists(test_microvm.jailer.api_socket_path())


def test_empty_jailer_id(test_microvm_with_api):
    """
    Test that the jailer ID cannot be empty.
    """
    test_microvm = test_microvm_with_api
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
        expected_err = (
            "Jailer error: Invalid instance ID: Invalid len (0);"
            "  the length must be between 1 and 64"
        )
        assert expected_err in str(err)


def test_exec_file_not_exist(test_microvm_with_api, tmp_path):
    """
    Test the jailer option `--exec-file`
    """
    test_microvm = test_microvm_with_api

    # Error case 1: No such file exists
    pseudo_exec_file_path = tmp_path / "pseudo_firecracker_exec_file"
    test_microvm.jailer.exec_file = pseudo_exec_file_path

    with pytest.raises(
        Exception,
        match=rf"Jailer error: Failed to canonicalize path {pseudo_exec_file_path}:"
        rf" No such file or directory \(os error 2\)",
    ):
        test_microvm.spawn()

    # Error case 2: Not a file
    pseudo_exec_dir_path = tmp_path / "firecracker_test_dir"
    pseudo_exec_dir_path.mkdir()
    test_microvm.jailer.exec_file = pseudo_exec_dir_path

    with pytest.raises(
        Exception,
        match=rf"Jailer error: {pseudo_exec_dir_path} is not a file",
    ):
        test_microvm.spawn()

    # Error case 3: Filename without "firecracker"
    pseudo_exec_file_path = tmp_path / "foobarbaz"
    pseudo_exec_file_path.touch()
    test_microvm.jailer.exec_file = pseudo_exec_file_path

    with pytest.raises(
        Exception,
        match=r"Jailer error: Invalid filename. The filename of `--exec-file` option"
        r' must contain "firecracker": foobarbaz',
    ):
        test_microvm.spawn()


def test_default_chroot_hierarchy(test_microvm_with_api):
    """
    Test the folder hierarchy created by default by the jailer.
    """
    test_microvm = test_microvm_with_api

    test_microvm.spawn()

    # We do checks for all the things inside the chroot that the jailer crates
    # by default.
    check_stats(
        test_microvm.jailer.chroot_path(),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev"),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev/net"),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "run"),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev/net/tun"),
        CHAR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev/kvm"),
        CHAR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "firecracker"), FILE_STATS, 0, 0
    )


def test_arbitrary_usocket_location(test_microvm_with_api):
    """
    Test arbitrary location scenario for the api socket.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.extra_args = {"api-sock": "api.socket"}

    test_microvm.spawn()

    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "api.socket"),
        SOCK_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )


@functools.lru_cache(maxsize=None)
def cgroup_v2_available():
    """Check if cgroup-v2 is enabled on the system."""
    # https://rootlesscontaine.rs/getting-started/common/cgroup2/#checking-whether-cgroup-v2-is-already-enabled
    return os.path.isfile("/sys/fs/cgroup/cgroup.controllers")


@pytest.fixture(scope="session", autouse=True)
def sys_setup_cgroups():
    """Configure cgroupfs in order to run the tests.

    This fixture sets up the cgroups on the system to enable processes
    spawned by the tests be able to create cgroups successfully.
    This set-up is important to do when running from inside a Docker
    container while the system is using cgroup-v2.
    """
    cgroup_version = 2 if cgroup_v2_available() else 1
    yield cgroup_version


def check_cgroups_v1(cgroups, cgroup_location, jailer_id, parent_cgroup=FC_BINARY_NAME):
    """Assert that every cgroupv1 in cgroups is correctly set."""
    for cgroup in cgroups:
        controller = cgroup.split(".")[0]
        file_name, value = cgroup.split("=")
        location = cgroup_location + "/{}/{}/{}/".format(
            controller, parent_cgroup, jailer_id
        )
        tasks_file = location + "tasks"
        file = location + file_name

        assert open(file, "r", encoding="utf-8").readline().strip() == value
        assert open(tasks_file, "r", encoding="utf-8").readline().strip().isdigit()


def check_cgroups_v2(cgroups, cgroup_location, jailer_id, parent_cgroup=FC_BINARY_NAME):
    """Assert that every cgroupv2 in cgroups is correctly set."""
    cg_locations = {
        "root": f"{cgroup_location}",
        "fc": f"{cgroup_location}/{parent_cgroup}",
        "jail": f"{cgroup_location}/{parent_cgroup}/{jailer_id}",
    }
    for cgroup in cgroups:
        controller = cgroup.split(".")[0]
        file_name, value = cgroup.split("=")
        procs_file = f'{cg_locations["jail"]}/cgroup.procs'
        file = f'{cg_locations["jail"]}/{file_name}'

        assert (
            controller
            in open(f'{cg_locations["root"]}/cgroup.controllers', "r", encoding="utf-8")
            .readline()
            .strip()
        )
        assert (
            controller
            in open(
                f'{cg_locations["root"]}/cgroup.subtree_control', "r", encoding="utf-8"
            )
            .readline()
            .strip()
        )
        assert (
            controller
            in open(f'{cg_locations["fc"]}/cgroup.controllers', "r", encoding="utf-8")
            .readline()
            .strip()
        )
        assert (
            controller
            in open(
                f'{cg_locations["fc"]}/cgroup.subtree_control', "r", encoding="utf-8"
            )
            .readline()
            .strip()
        )
        assert (
            controller
            in open(f'{cg_locations["jail"]}/cgroup.controllers', "r", encoding="utf-8")
            .readline()
            .strip()
        )
        assert open(file, "r", encoding="utf-8").readline().strip() == value
        assert open(procs_file, "r", encoding="utf-8").readline().strip().isdigit()


def get_cpus(node):
    """Retrieve CPUs from NUMA node."""
    sys_node = "/sys/devices/system/node/node" + str(node)
    assert os.path.isdir(sys_node)
    node_cpus_path = sys_node + "/cpulist"

    return open(node_cpus_path, "r", encoding="utf-8").readline().strip()


def check_limits(pid, no_file, fsize):
    """Verify resource limits against expected values."""
    # Fetch firecracker process limits for number of open fds
    (soft, hard) = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    assert soft == no_file
    assert hard == no_file

    # Fetch firecracker process limits for maximum file size
    (soft, hard) = resource.prlimit(pid, resource.RLIMIT_FSIZE)
    assert soft == fsize
    assert hard == fsize


def test_cgroups(test_microvm_with_api, sys_setup_cgroups):
    """
    Test the cgroups are correctly set by the jailer.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.cgroup_ver = sys_setup_cgroups
    if test_microvm.jailer.cgroup_ver == 2:
        test_microvm.jailer.cgroups = ["cpu.weight.nice=10"]
    else:
        test_microvm.jailer.cgroups = ["cpu.shares=2", "cpu.cfs_period_us=200000"]

    # Retrieve CPUs from NUMA node 0.
    node_cpus = get_cpus(0)

    # Appending the cgroups for numa node 0.
    test_microvm.jailer.cgroups = test_microvm.jailer.cgroups + [
        "cpuset.mems=0",
        "cpuset.cpus={}".format(node_cpus),
    ]

    test_microvm.spawn()

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = "/sys/fs/cgroup"
    assert os.path.isdir(sys_cgroup)

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(
            test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
        )
    else:
        check_cgroups_v2(
            test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
        )


def test_cgroups_custom_parent(test_microvm_with_api, sys_setup_cgroups):
    """
    Test cgroups when a custom parent cgroup is used.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.cgroup_ver = sys_setup_cgroups
    test_microvm.jailer.parent_cgroup = "custom_cgroup/group2"
    if test_microvm.jailer.cgroup_ver == 2:
        test_microvm.jailer.cgroups = ["cpu.weight=2"]
    else:
        test_microvm.jailer.cgroups = ["cpu.shares=2", "cpu.cfs_period_us=200000"]

    # Retrieve CPUs from NUMA node 0.
    node_cpus = get_cpus(0)

    test_microvm.jailer.cgroups = test_microvm.jailer.cgroups + [
        "cpuset.mems=0",
        "cpuset.cpus={}".format(node_cpus),
    ]

    test_microvm.spawn()

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = "/sys/fs/cgroup"
    assert os.path.isdir(sys_cgroup)

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(
            test_microvm.jailer.cgroups,
            sys_cgroup,
            test_microvm.jailer.jailer_id,
            test_microvm.jailer.parent_cgroup,
        )
    else:
        check_cgroups_v2(
            test_microvm.jailer.cgroups,
            sys_cgroup,
            test_microvm.jailer.jailer_id,
            test_microvm.jailer.parent_cgroup,
        )


def test_node_cgroups(test_microvm_with_api, sys_setup_cgroups):
    """
    Test the numa node cgroups are correctly set by the jailer.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.cgroup_ver = sys_setup_cgroups

    # Retrieve CPUs from NUMA node 0.
    node_cpus = get_cpus(0)

    # Appending the cgroups for numa node 0
    test_microvm.jailer.cgroups = ["cpuset.mems=0", "cpuset.cpus={}".format(node_cpus)]

    test_microvm.spawn()

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = "/sys/fs/cgroup"
    assert os.path.isdir(sys_cgroup)

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(
            test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
        )
    else:
        check_cgroups_v2(
            test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
        )


def test_cgroups_without_numa(test_microvm_with_api, sys_setup_cgroups):
    """
    Test the cgroups are correctly set by the jailer, without numa assignment.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.cgroup_ver = sys_setup_cgroups
    if test_microvm.jailer.cgroup_ver == 2:
        test_microvm.jailer.cgroups = ["cpu.weight=2"]
    else:
        test_microvm.jailer.cgroups = ["cpu.shares=2", "cpu.cfs_period_us=200000"]

    test_microvm.spawn()

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = "/sys/fs/cgroup"
    assert os.path.isdir(sys_cgroup)

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(
            test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
        )
    else:
        check_cgroups_v2(
            test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
        )


@pytest.mark.skipif(
    cgroup_v2_available() is True, reason="Requires system with cgroup-v1 enabled."
)
def test_v1_default_cgroups(test_microvm_with_api):
    """
    Test if the jailer is using cgroup-v1 by default.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.cgroups = ["cpu.shares=2"]

    test_microvm.spawn()

    # We assume sysfs cgroups are mounted here.
    sys_cgroup = "/sys/fs/cgroup"
    assert os.path.isdir(sys_cgroup)

    check_cgroups_v1(
        test_microvm.jailer.cgroups, sys_cgroup, test_microvm.jailer.jailer_id
    )


def test_args_default_resource_limits(test_microvm_with_api):
    """
    Test the default resource limits are correctly set by the jailer.
    """
    test_microvm = test_microvm_with_api

    test_microvm.spawn()

    # Get firecracker's PID
    pid = int(test_microvm.jailer_clone_pid)
    assert pid != 0

    # Fetch firecracker process limits for number of open fds
    (soft, hard) = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    # Check that the default limit was set.
    assert soft == 2048
    assert hard == 2048

    # Fetch firecracker process limits for number of open fds
    (soft, hard) = resource.prlimit(pid, resource.RLIMIT_FSIZE)
    # Check that no limit was set
    assert soft == -1
    assert hard == -1


def test_args_resource_limits(test_microvm_with_api):
    """
    Test the resource limits are correctly set by the jailer.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.resource_limits = RESOURCE_LIMITS

    test_microvm.spawn()

    # Get firecracker's PID
    pid = int(test_microvm.jailer_clone_pid)
    assert pid != 0

    # Check limit values were correctly set.
    check_limits(pid, NOFILE, FSIZE)


def test_negative_file_size_limit(uvm_plain):
    """
    Test creating snapshot file fails when size exceeds `fsize` limit.
    """
    test_microvm = uvm_plain
    # limit to 1MB, to account for logs and metrics
    test_microvm.jailer.resource_limits = [f"fsize={2**20}"]
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.start()

    test_microvm.pause()

    # Attempt to create a snapshot.
    try:
        test_microvm.api.snapshot_create.put(
            mem_file_path="/vm.mem",
            snapshot_path="/vm.vmstate",
        )
    except (
        http_client.RemoteDisconnected,
        urllib3.exceptions.ProtocolError,
        requests.exceptions.ConnectionError,
    ) as _error:
        test_microvm.expect_kill_by_signal = True
        # Check the microVM received signal `SIGXFSZ` (25),
        # which corresponds to exceeding file size limit.
        msg = "Shutting down VM after intercepting signal 25, code 0"
        test_microvm.check_log_message(msg)
        time.sleep(1)
        # Check that the process was terminated.
        assert not psutil.pid_exists(test_microvm.jailer_clone_pid)
    else:
        assert False, "Negative test failed"


def test_negative_no_file_limit(test_microvm_with_api):
    """
    Test microVM is killed when exceeding `no-file` limit.
    """
    test_microvm = test_microvm_with_api
    test_microvm.jailer.resource_limits = ["no-file=3"]

    # pylint: disable=W0703
    try:
        test_microvm.spawn()
    except Exception as error:
        assert "No file descriptors available (os error 24)" in str(error)
        assert test_microvm.jailer_clone_pid is None
    else:
        assert False, "Negative test failed"


def test_new_pid_ns_resource_limits(test_microvm_with_api):
    """
    Test that Firecracker process inherits jailer resource limits.
    """
    test_microvm = test_microvm_with_api

    test_microvm.jailer.new_pid_ns = True
    test_microvm.jailer.resource_limits = RESOURCE_LIMITS

    test_microvm.spawn()

    # Get Firecracker's PID.
    fc_pid = test_microvm.pid_in_new_ns

    # Check limit values were correctly set.
    check_limits(fc_pid, NOFILE, FSIZE)


def test_new_pid_namespace(test_microvm_with_api):
    """
    Test that Firecracker is spawned in a new PID namespace if requested.
    """
    test_microvm = test_microvm_with_api

    test_microvm.jailer.new_pid_ns = True

    test_microvm.spawn()

    # Check that the PID file exists.
    fc_pid = test_microvm.pid_in_new_ns

    # Validate the PID.
    stdout = subprocess.check_output("pidof firecracker", shell=True)
    assert str(fc_pid) in stdout.strip().decode()

    # Get the thread group IDs in each of the PID namespaces of which
    # Firecracker process is a member of.
    nstgid_cmd = "cat /proc/{}/status | grep NStgid".format(fc_pid)
    nstgid_list = (
        subprocess.check_output(nstgid_cmd, shell=True)
        .decode("utf-8")
        .strip()
        .split("\t")[1:]
    )

    # Check that Firecracker's PID namespace is nested. `NStgid` should
    # report two values and the last one should be 1, because Firecracker
    # becomes the init(1) process of the new PID namespace it is spawned in.
    assert len(nstgid_list) == 2
    assert int(nstgid_list[1]) == 1
    assert int(nstgid_list[0]) == fc_pid
