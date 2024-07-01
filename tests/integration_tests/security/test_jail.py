# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the jailer's behavior."""

import http.client as http_client
import os
import resource
import stat
import subprocess
import time
from pathlib import Path

import pytest
import requests
import urllib3

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


def test_empty_jailer_id(uvm_plain):
    """
    Test that the jailer ID cannot be empty.
    """
    test_microvm = uvm_plain

    # Set the jailer ID to None.
    test_microvm.jailer = JailerContext(
        jailer_id="",
        exec_file=test_microvm.fc_binary_path,
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


def test_exec_file_not_exist(uvm_plain, tmp_path):
    """
    Test the jailer option `--exec-file`
    """
    test_microvm = uvm_plain

    # Error case 1: No such file exists
    pseudo_exec_file_path = tmp_path / "pseudo_firecracker_exec_file"
    fc_dir = Path("/srv/jailer") / pseudo_exec_file_path.name / test_microvm.id
    fc_dir.mkdir(parents=True, exist_ok=True)
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
    fc_dir = Path("/srv/jailer") / pseudo_exec_dir_path.name / test_microvm.id
    fc_dir.mkdir(parents=True, exist_ok=True)
    test_microvm.jailer.exec_file = pseudo_exec_dir_path

    with pytest.raises(
        Exception,
        match=rf"Jailer error: {pseudo_exec_dir_path} is not a file",
    ):
        test_microvm.spawn()

    # Error case 3: Filename without "firecracker"
    pseudo_exec_file_path = tmp_path / "foobarbaz"
    pseudo_exec_file_path.touch()
    fc_dir = Path("/srv/jailer") / pseudo_exec_file_path.name / test_microvm.id
    fc_dir.mkdir(parents=True, exist_ok=True)
    test_microvm.jailer.exec_file = pseudo_exec_file_path

    with pytest.raises(
        Exception,
        match=r"Jailer error: Invalid filename. The filename of `--exec-file` option"
        r' must contain "firecracker": foobarbaz',
    ):
        test_microvm.spawn()


def test_default_chroot_hierarchy(uvm_plain):
    """
    Test the folder hierarchy created by default by the jailer.
    """
    test_microvm = uvm_plain

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


def test_arbitrary_usocket_location(uvm_plain):
    """
    Test arbitrary location scenario for the api socket.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.extra_args = {"api-sock": "api.socket"}

    test_microvm.spawn()

    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "api.socket"),
        SOCK_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )


class Cgroups:
    """Helper class to work with cgroups"""

    def __init__(self):
        self.root = Path("/sys/fs/cgroup")
        self.version = 2
        # https://rootlesscontaine.rs/getting-started/common/cgroup2/#checking-whether-cgroup-v2-is-already-enabled
        if not self.root.joinpath("cgroup.controllers").exists():
            self.version = 1

    def new_cgroup(self, cgname):
        """Create a new cgroup"""
        self.root.joinpath(cgname).mkdir(parents=True)

    def move_pid(self, cgname, pid):
        """Move a PID to a cgroup"""
        cg_pids = self.root.joinpath(f"{cgname}/cgroup.procs")
        cg_pids.write_text(f"{pid}\n", encoding="ascii")


@pytest.fixture(scope="session", autouse=True)
def cgroups_info():
    """Return a fixture with the cgroups available in the system"""
    return Cgroups()


def check_cgroups_v1(cgroups, jailer_id, parent_cgroup=FC_BINARY_NAME):
    """Assert that every cgroupv1 in cgroups is correctly set."""
    # We assume sysfs cgroups are mounted here.
    cgroup_location = "/sys/fs/cgroup"
    assert os.path.isdir(cgroup_location)

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


def check_cgroups_v2(vm):
    """Assert that every cgroupv2 in cgroups is correctly set."""
    cg = Cgroups()
    assert cg.root.is_dir()
    parent_cgroup = vm.jailer.parent_cgroup
    if parent_cgroup is None:
        parent_cgroup = FC_BINARY_NAME
    cg_parent = cg.root / parent_cgroup
    cg_jail = cg_parent / vm.jailer.jailer_id

    # if no cgroups were specified, then the jailer should move the FC process
    # to the parent group
    if len(vm.jailer.cgroups) == 0:
        procs = cg_parent.joinpath("cgroup.procs").read_text().splitlines()
        assert str(vm.firecracker_pid) in procs

    for cgroup in vm.jailer.cgroups:
        controller = cgroup.split(".")[0]
        file_name, value = cgroup.split("=")
        procs = cg_jail.joinpath("cgroup.procs").read_text().splitlines()
        file = cg_jail / file_name

        assert file.read_text().strip() == value

        assert all(x.isnumeric() for x in procs)
        assert str(vm.firecracker_pid) in procs

        for cgroup in [cg.root, cg_parent, cg_jail]:
            assert controller in cgroup.joinpath("cgroup.controllers").read_text(
                encoding="ascii"
            )
            # don't check since there are no children cgroups
            if cgroup == cg_jail:
                continue
            assert controller in cgroup.joinpath("cgroup.subtree_control").read_text(
                encoding="ascii"
            )


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


def test_cgroups(uvm_plain, cgroups_info):
    """
    Test the cgroups are correctly set by the jailer.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.cgroup_ver = cgroups_info.version
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

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(test_microvm.jailer.cgroups, test_microvm.jailer.jailer_id)
    else:
        check_cgroups_v2(test_microvm)


def test_cgroups_custom_parent(uvm_plain, cgroups_info):
    """
    Test cgroups when a custom parent cgroup is used.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.cgroup_ver = cgroups_info.version
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

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(
            test_microvm.jailer.cgroups,
            test_microvm.jailer.jailer_id,
            test_microvm.jailer.parent_cgroup,
        )
    else:
        check_cgroups_v2(test_microvm)


def test_node_cgroups(uvm_plain, cgroups_info):
    """
    Test the numa node cgroups are correctly set by the jailer.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.cgroup_ver = cgroups_info.version

    # Retrieve CPUs from NUMA node 0.
    node_cpus = get_cpus(0)

    # Appending the cgroups for numa node 0
    test_microvm.jailer.cgroups = ["cpuset.mems=0", "cpuset.cpus={}".format(node_cpus)]

    test_microvm.spawn()

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(test_microvm.jailer.cgroups, test_microvm.jailer.jailer_id)
    else:
        check_cgroups_v2(test_microvm)


def test_cgroups_without_numa(uvm_plain, cgroups_info):
    """
    Test the cgroups are correctly set by the jailer, without numa assignment.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.cgroup_ver = cgroups_info.version
    if test_microvm.jailer.cgroup_ver == 2:
        test_microvm.jailer.cgroups = ["cpu.weight=2"]
    else:
        test_microvm.jailer.cgroups = ["cpu.shares=2", "cpu.cfs_period_us=200000"]

    test_microvm.spawn()

    if test_microvm.jailer.cgroup_ver == 1:
        check_cgroups_v1(test_microvm.jailer.cgroups, test_microvm.jailer.jailer_id)
    else:
        check_cgroups_v2(test_microvm)


def test_v1_default_cgroups(uvm_plain, cgroups_info):
    """
    Test if the jailer is using cgroup-v1 by default.
    """
    if cgroups_info.version != 1:
        pytest.skip(reason="Requires system with cgroup-v1 enabled.")
    test_microvm = uvm_plain
    test_microvm.jailer.cgroups = ["cpu.shares=2"]
    test_microvm.spawn()
    check_cgroups_v1(test_microvm.jailer.cgroups, test_microvm.jailer.jailer_id)


def test_cgroups_custom_parent_move(uvm_plain, cgroups_info):
    """
    Test cgroups when a custom parent cgroup is used and no cgroups are specified

    In this case we just want to move under the parent cgroup
    """
    if cgroups_info.version != 2:
        pytest.skip("cgroupsv2 only")
    test_microvm = uvm_plain
    test_microvm.jailer.cgroup_ver = cgroups_info.version
    # Make it somewhat unique so it doesn't conflict with other test runs
    parent_cgroup = f"custom_cgroup/{test_microvm.id[:8]}"
    test_microvm.jailer.parent_cgroup = parent_cgroup

    cgroups_info.new_cgroup(parent_cgroup)
    test_microvm.spawn()
    check_cgroups_v2(test_microvm)


def test_args_default_resource_limits(uvm_plain):
    """
    Test the default resource limits are correctly set by the jailer.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    # Get firecracker's PID
    pid = test_microvm.firecracker_pid
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


def test_args_resource_limits(uvm_plain):
    """
    Test the resource limits are correctly set by the jailer.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = RESOURCE_LIMITS
    test_microvm.spawn()
    # Get firecracker's PID
    pid = test_microvm.firecracker_pid
    assert pid != 0

    # Check limit values were correctly set.
    check_limits(pid, NOFILE, FSIZE)


def test_positive_file_size_limit(uvm_plain):
    """
    Test creating vm succeeds when memory size is under `fsize` limit.
    """

    vm_mem_size = 128
    jail_limit = (vm_mem_size + 1) << 20

    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = [f"fsize={jail_limit}"]
    test_microvm.spawn()
    test_microvm.basic_config(mem_size_mib=vm_mem_size)

    # Attempt to start a vm.
    test_microvm.start()


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
        # Check the microVM received signal `SIGXFSZ` (25),
        # which corresponds to exceeding file size limit.
        msg = "Shutting down VM after intercepting signal 25, code 0"
        test_microvm.check_log_message(msg)
        time.sleep(1)

        test_microvm.mark_killed()
    else:
        assert False, "Negative test failed"


def test_negative_no_file_limit(uvm_plain):
    """
    Test microVM is killed when exceeding `no-file` limit.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = ["no-file=3"]

    # pylint: disable=W0703
    try:
        test_microvm.spawn()
    except ChildProcessError as error:
        assert "No file descriptors available (os error 24)" in str(error)

        test_microvm.mark_killed()
    else:
        assert False, "Negative test failed"


def test_new_pid_ns_resource_limits(uvm_plain):
    """
    Test that Firecracker process inherits jailer resource limits.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = RESOURCE_LIMITS
    test_microvm.spawn()

    # Get Firecracker's PID.
    fc_pid = test_microvm.firecracker_pid

    # Check limit values were correctly set.
    check_limits(fc_pid, NOFILE, FSIZE)


def test_new_pid_namespace(uvm_plain):
    """
    Test that Firecracker is spawned in a new PID namespace if requested.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    # Check that the PID file exists.
    fc_pid = test_microvm.firecracker_pid

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


@pytest.mark.parametrize(
    "daemonize",
    [True, False],
)
@pytest.mark.parametrize(
    "new_pid_ns",
    [True, False],
)
def test_firecracker_kill_by_pid(uvm_plain, daemonize, new_pid_ns):
    """
    Test that Firecracker is spawned in a new PID namespace if requested.
    """
    microvm = uvm_plain
    microvm.jailer.daemonize = daemonize
    microvm.jailer.new_pid_ns = new_pid_ns
    microvm.spawn()
    microvm.basic_config()
    microvm.add_net_iface()
    microvm.start()
    microvm.wait_for_up()

    # before killing microvm make sure the Jailer config is what we set it to be.
    assert (
        microvm.jailer.daemonize == daemonize
        and microvm.jailer.new_pid_ns == new_pid_ns
    )
    microvm.kill()
