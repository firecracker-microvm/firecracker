# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generic utility functions that are used in the framework."""
import functools
import json
import logging
import os
import platform
import re
import signal
import stat
import subprocess
import time
import typing
from collections import defaultdict, namedtuple
from contextlib import contextmanager
from pathlib import Path
from typing import Dict

import packaging.version
import psutil
from tenacity import (
    Retrying,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from framework.defs import MIN_KERNEL_VERSION_FOR_IO_URING

FLUSH_CMD = 'screen -S {session} -X colon "logfile flush 0^M"'
CommandReturn = namedtuple("CommandReturn", "returncode stdout stderr")
CMDLOG = logging.getLogger("commands")
GET_CPU_LOAD = "top -bn1 -H -p {} -w512 | tail -n+8"


def get_threads(pid: int) -> dict:
    """Return dict consisting of child threads."""
    threads_map = defaultdict(list)
    proc = psutil.Process(pid)
    for thread in proc.threads():
        threads_map[psutil.Process(thread.id).name()].append(thread.id)
    return threads_map


def get_cpu_affinity(pid: int) -> list:
    """Get CPU affinity for a thread."""
    return psutil.Process(pid).cpu_affinity()


def set_cpu_affinity(pid: int, cpulist: list) -> list:
    """Set CPU affinity for a thread."""
    real_cpulist = list(map(CpuMap, cpulist))
    return psutil.Process(pid).cpu_affinity(real_cpulist)


def get_cpu_utilization(pid: int) -> Dict[str, float]:
    """Return current process per thread CPU utilization."""
    _, stdout, _ = check_output(GET_CPU_LOAD.format(pid))
    cpu_utilization = {}

    # Take all except the last line
    lines = stdout.strip().split(sep="\n")
    for line in lines:
        # sometimes the firecracker process will have gone away, in which case top does not return anything
        if not line:
            continue

        info = line.strip().split()
        # We need at least CPU utilization and threads names cols (which
        # might be two cols e.g `fc_vcpu 0`).
        info_len = len(info)
        assert info_len > 11, line

        cpu_percent = float(info[8])

        # Handles `fc_vcpu 0` case as well.
        thread_name = info[11] + (" " + info[12] if info_len > 12 else "")
        cpu_utilization[thread_name] = cpu_percent

    return cpu_utilization


def track_cpu_utilization(
    pid: int, iterations: int, omit: int
) -> Dict[str, list[float]]:
    """Tracks cpu utilization of a process for certain number of
    iterations. Sleeps for first `omit` seconds.
    """
    assert iterations > 0

    # Sleep first `omit` secconds
    time.sleep(omit)

    cpu_utilization = {}
    for _ in range(iterations):
        current_cpu_utilization = get_cpu_utilization(pid)
        assert len(current_cpu_utilization) > 0

        for thread_name, value in current_cpu_utilization.items():
            if not cpu_utilization.get(thread_name):
                cpu_utilization[thread_name] = []
            cpu_utilization[thread_name].append(value)

        # 1 second granularity
        time.sleep(1)
    return cpu_utilization


@contextmanager
def chroot(path):
    """
    Create a chroot environment for running some code
    """

    # Need to keep these around so we can exit the chroot
    real_root = os.open("/", os.O_RDONLY)
    working_dir = os.getcwd()

    try:
        # Jump in the chroot
        os.chroot(path)
        os.chdir("/")
        yield

    finally:
        # Jump out of the chroot
        os.fchdir(real_root)
        os.chroot(".")
        os.chdir(working_dir)


class UffdHandler:
    """Describe the UFFD page fault handler process."""

    def __init__(self, name, socket_path, mem_file, chroot_path, log_file_name):
        """Instantiate the handler process with arguments."""
        self._proc = None
        self._handler_name = name
        self._socket_path = socket_path
        self._mem_file = mem_file
        self._chroot = chroot_path
        self._log_file = log_file_name

    def spawn(self, uid, gid):
        """Spawn handler process using arguments provided."""

        with chroot(self._chroot):
            st = os.stat(self._handler_name)
            os.chmod(self._handler_name, st.st_mode | stat.S_IEXEC)

            chroot_log_file = Path("/") / self._log_file
            with open(chroot_log_file, "w", encoding="utf-8") as logfile:
                args = [f"/{self._handler_name}", self._socket_path, self._mem_file]
                self._proc = subprocess.Popen(
                    args, stdout=logfile, stderr=subprocess.STDOUT
                )

            # Give it time start and fail, if it really has too (bad things happen).
            time.sleep(1)
            if not self.is_running():
                print(chroot_log_file.read_text(encoding="utf-8"))
                assert False, "Could not start PF handler!"

            # The page fault handler will create the socket path with root rights.
            # Change rights to the jailer's.
            os.chown(self._socket_path, uid, gid)

    @property
    def proc(self):
        """Return UFFD handler process."""
        return self._proc

    def is_running(self):
        """Check if UFFD process is running"""
        return self.proc is not None and self.proc.poll() is None

    @property
    def log_file(self):
        """Return the path to the UFFD handler's log file"""
        return Path(self._chroot) / Path(self._log_file)

    @property
    def log_data(self):
        """Return the log data of the UFFD handler"""
        if self.log_file is None:
            return ""
        return self.log_file.read_text(encoding="utf-8")

    def __del__(self):
        """Tear down the UFFD handler process."""
        if self.proc is not None:
            self.proc.kill()


# pylint: disable=too-few-public-methods
class CpuMap:
    """Cpu map from real cpu cores to containers visible cores.

    When a docker container is restricted in terms of assigned cpu cores,
    the information from `/proc/cpuinfo` will present all the cpu cores
    of the machine instead of showing only the container assigned cores.
    This class maps the real assigned host cpu cores to virtual cpu cores,
    starting from 0.
    """

    arr = []

    def __new__(cls, cpu):
        """Instantiate the class field."""
        assert CpuMap.len() > cpu
        if not CpuMap.arr:
            CpuMap.arr = CpuMap._cpus()
        return CpuMap.arr[cpu]

    @staticmethod
    def len():
        """Get the host cpus count."""
        if not CpuMap.arr:
            CpuMap.arr = CpuMap._cpus()
        return len(CpuMap.arr)

    @classmethod
    def _cpus(cls):
        """Obtain the real processor map.

        See this issue for details:
        https://github.com/moby/moby/issues/20770.
        """
        # The real processor map is found at different paths based on cgroups version:
        #  - cgroupsv1: /cpuset.cpus
        #  - cgroupsv2: /cpuset.cpus.effective
        # For more details, see https://docs.kernel.org/admin-guide/cgroup-v2.html#cpuset-interface-files
        cpulist = None
        for path in [
            Path("/sys/fs/cgroup/cpuset/cpuset.cpus"),
            Path("/sys/fs/cgroup/cpuset.cpus.effective"),
        ]:
            if path.exists():
                cpulist = path.read_text("ascii").strip()
                break
        else:
            raise RuntimeError("Could not find cgroups cpuset")
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


class CmdBuilder:
    """Command builder class."""

    def __init__(self, bin_path):
        """Initialize the command builder."""
        self._bin_path = bin_path
        self._args = {}

    def with_arg(self, flag, value=""):
        """Add a new argument."""
        self._args[flag] = value
        return self

    def build(self):
        """Build the command."""
        cmd = self._bin_path + " "
        for flag, value in self._args.items():
            cmd += f"{flag} {value} "
        return cmd


def search_output_from_cmd(cmd: str, find_regex: typing.Pattern) -> typing.Match:
    """
    Run a shell command and search a given regex object in stdout.

    If the regex object is not found, a RuntimeError exception is raised.

    :param cmd: command to run
    :param find_regex: regular expression object to search for
    :return: result of re.search()
    """
    # Run the given command in a shell
    _, stdout, _ = check_output(cmd)

    # Search for the object
    content = re.search(find_regex, stdout)

    # If the result is not None, return it
    if content:
        return content

    raise RuntimeError(
        "Could not find '%s' in output for '%s'" % (find_regex.pattern, cmd)
    )


def get_free_mem_ssh(ssh_connection):
    """
    Get how much free memory in kB a guest sees, over ssh.

    :param ssh_connection: connection to the guest
    :return: available mem column output of 'free'
    """
    _, stdout, stderr = ssh_connection.run("cat /proc/meminfo | grep MemAvailable")
    assert stderr == ""

    # Split "MemAvailable:   123456 kB" and validate it
    meminfo_data = stdout.split()
    if len(meminfo_data) == 3:
        # Return the middle element in the array
        return int(meminfo_data[1])

    raise Exception("Available memory not found in `/proc/meminfo")


def _format_output_message(proc, stdout, stderr):
    output_message = f"\n[{proc.pid}] Command:\n{proc.args}"
    # Append stdout/stderr to the output message
    if stdout != "":
        output_message += f"\n[{proc.pid}] stdout:\n{stdout.decode()}"
    if stderr != "":
        output_message += f"\n[{proc.pid}] stderr:\n{stderr.decode()}"
    output_message += f"\nReturned error code: {proc.returncode}"
    return output_message


def run_cmd(cmd, check=False, shell=True, cwd=None, timeout=None) -> CommandReturn:
    """
    Execute a given command.

    :param cmd: command to execute
    :param check: whether a non-zero return code should result in a `ChildProcessError` or not.
    :param no_shell: don't run the command in a sub-shell
    :param cwd: sets the current directory before the child is executed
    :param timeout: Time before command execution should be aborted with a `TimeoutExpired` exception
    :return: return code, stdout, stderr
    """
    if isinstance(cmd, list) or not shell:
        # Create the async process
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
        )
    else:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
        )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

        # Log the message with one call so that multiple statuses
        # don't get mixed up
        CMDLOG.warning(
            "Timeout executing command: %s\n",
            _format_output_message(proc, stdout, stderr),
        )

        raise

    output_message = _format_output_message(proc, stdout, stderr)

    # If a non-zero return code was thrown, raise an exception
    if check and proc.returncode != 0:
        CMDLOG.warning("Command failed: %s\n", output_message)

        raise ChildProcessError(output_message)

    CMDLOG.debug(output_message)

    return CommandReturn(proc.returncode, stdout.decode(), stderr.decode())


def check_output(cmd, shell=True, cwd=None, timeout=None) -> CommandReturn:
    """Identical to `run_cmd`, but always sets `check_output` to `True`."""
    return run_cmd(cmd, True, shell, cwd, timeout)


def assert_seccomp_level(pid, seccomp_level):
    """Test that seccomp_level applies to all threads of a process."""
    # Get number of threads
    cmd = "ps -T --no-headers -p {} | awk '{{print $2}}'".format(pid)
    process = check_output(cmd)
    threads_out_lines = process.stdout.splitlines()
    for tid in threads_out_lines:
        # Verify each thread's Seccomp status
        cmd = "cat /proc/{}/status | grep Seccomp:".format(tid)
        process = check_output(cmd)
        seccomp_line = "".join(process.stdout.split())
        assert seccomp_line == "Seccomp:" + seccomp_level


def run_guest_cmd(ssh_connection, cmd, expected, use_json=False):
    """Runs a shell command at the remote accessible via SSH"""
    _, stdout, stderr = ssh_connection.check_output(cmd)
    assert stderr == ""
    stdout = stdout if not use_json else json.loads(stdout)
    assert stdout == expected


@retry(wait=wait_fixed(1), stop=stop_after_attempt(10), reraise=True)
def wait_process_termination(p_pid):
    """Wait for a process to terminate.

    Will return sucessfully if the process
    got indeed killed or raises an exception if the process
    is still alive after retrying several times.
    """
    if psutil.pid_exists(p_pid):
        raise Exception(f"[{p_pid}] process is still alive")


def get_firecracker_version_from_toml():
    """
    Return the version of the firecracker crate, from Cargo.toml.

    Should be the same as the output of `./firecracker --version`, if
    the code has not been released.
    """
    cmd = "cd ../src/firecracker && cargo pkgid | cut -d# -f2 | cut -d: -f2"
    _, stdout, _ = check_output(cmd)
    return packaging.version.parse(stdout)


def get_kernel_version(level=2):
    """Return the current kernel version in format `major.minor.patch`."""
    linux_version = platform.release()
    actual_level = 0
    for idx, char in enumerate(linux_version):
        if char == ".":
            actual_level += 1
        if actual_level > level or (not char.isdigit() and char != "."):
            linux_version = linux_version[0:idx]
            break
    return linux_version


def is_io_uring_supported():
    """
    Return whether Firecracker supports io_uring for the running kernel ...

    ...version.
    """
    kv = packaging.version.parse(get_kernel_version())
    min_kv = packaging.version.parse(MIN_KERNEL_VERSION_FOR_IO_URING)
    return kv >= min_kv


def generate_mmds_session_token(ssh_connection, ipv4_address, token_ttl):
    """Generate session token used for MMDS V2 requests."""
    cmd = "curl -m 2 -s"
    cmd += " -X PUT"
    cmd += ' -H  "X-metadata-token-ttl-seconds: {}"'.format(token_ttl)
    cmd += " http://{}/latest/api/token".format(ipv4_address)
    _, stdout, _ = ssh_connection.run(cmd)
    token = stdout

    return token


def generate_mmds_get_request(ipv4_address, token=None, app_json=True):
    """Build `GET` request to fetch metadata from MMDS."""
    cmd = "curl -m 2 -s"

    if token is not None:
        cmd += " -X GET"
        cmd += ' -H  "X-metadata-token: {}"'.format(token)

    if app_json:
        cmd += ' -H "Accept: application/json"'

    cmd += " http://{}/".format(ipv4_address)

    return cmd


def configure_mmds(test_microvm, iface_ids, version=None, ipv4_address=None):
    """Configure mmds service."""
    mmds_config = {"network_interfaces": iface_ids}

    if version is not None:
        mmds_config["version"] = version

    if ipv4_address:
        mmds_config["ipv4_address"] = ipv4_address

    response = test_microvm.api.mmds_config.put(**mmds_config)
    return response


def populate_data_store(test_microvm, data_store):
    """Populate the MMDS data store of the microvm with the provided data"""
    response = test_microvm.api.mmds.get()
    assert response.json() == {}

    test_microvm.api.mmds.put(**data_store)
    response = test_microvm.api.mmds.get()
    assert response.json() == data_store


def start_screen_process(screen_log, session_name, binary_path, binary_params):
    """Start binary process into a screen session."""
    start_cmd = "screen -L -Logfile {logfile} -dmS {session} {binary} {params}"
    start_cmd = start_cmd.format(
        logfile=screen_log,
        session=session_name,
        binary=binary_path,
        params=" ".join(binary_params),
    )

    check_output(start_cmd)

    # Build a regex object to match (number).session_name
    regex_object = re.compile(r"([0-9]+)\.{}".format(session_name))

    # Run 'screen -ls' in a retry loop, 30 times with a 1s delay between calls.
    # If the output of 'screen -ls' matches the regex object, it will return the
    # PID. Otherwise, a RuntimeError will be raised.
    for attempt in Retrying(
        retry=retry_if_exception_type(RuntimeError),
        stop=stop_after_attempt(30),
        wait=wait_fixed(1),
        reraise=True,
    ):
        with attempt:
            screen_pid = search_output_from_cmd(
                cmd="screen -ls", find_regex=regex_object
            ).group(1)

    # Make sure the screen process launched successfully
    # As the parent process for the binary.
    screen_ps = psutil.Process(int(screen_pid))
    wait_process_running(screen_ps)

    # Configure screen to flush stdout to file.
    check_output(FLUSH_CMD.format(session=session_name))

    return screen_pid


def guest_run_fio_iteration(ssh_connection, iteration):
    """Start FIO workload into a microVM."""
    fio = """fio --filename=/dev/vda --direct=1 --rw=randread --bs=4k \
        --ioengine=libaio --iodepth=16 --runtime=10 --numjobs=4 --time_based \
        --group_reporting --name=iops-test-job --eta-newline=1 --readonly \
        --output /tmp/fio{} > /dev/null &""".format(
        iteration
    )
    exit_code, _, stderr = ssh_connection.run(fio)
    assert exit_code == 0, stderr


def check_filesystem(ssh_connection, disk_fmt, disk):
    """Check for filesystem corruption inside a microVM."""
    if disk_fmt == "squashfs":
        return
    ssh_connection.check_output(f"fsck.{disk_fmt} -n {disk}")


def check_entropy(ssh_connection):
    """Check that we can get random numbers from /dev/hwrng"""
    ssh_connection.check_output("dd if=/dev/hwrng of=/dev/null bs=4096 count=1")


@retry(wait=wait_fixed(0.5), stop=stop_after_attempt(5), reraise=True)
def wait_process_running(process):
    """Wait for a process to run.

    Will return successfully if the process is in
    a running state and will otherwise raise an exception.
    """
    assert process.is_running()


class Timeout:
    """
    A Context Manager to timeout sections of code.

    >>> with Timeout(30):
    >>>     time.sleep(35)
    """

    def __init__(self, seconds, msg="Timed out"):
        self.seconds = seconds
        self.msg = msg

    def handle_timeout(self, signum, frame):
        """Handle SIGALRM signal"""
        raise TimeoutError()

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, _type, _value, _traceback):
        signal.alarm(0)
