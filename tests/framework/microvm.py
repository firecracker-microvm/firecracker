# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Classes for working with microVMs.

This module defines `Microvm`, which can be used to create, test drive, and
destroy microvms.

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
"""

# pylint:disable=too-many-lines

import json
import logging
import os
import re
import select
import shutil
import signal
import subprocess
import time
import uuid
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional

from tenacity import retry, stop_after_attempt, wait_fixed

import host_tools.cargo_build as build_tools
import host_tools.network as net_tools
from framework import utils
from framework.defs import MAX_API_CALL_DURATION_MS
from framework.http_api import Api
from framework.jailer import JailerContext
from framework.microvm_helpers import MicrovmHelpers
from framework.properties import global_props
from framework.utils_drive import VhostUserBlkBackend, VhostUserBlkBackendType
from host_tools.fcmetrics import FCMetricsMonitor
from host_tools.memory import MemoryMonitor

LOG = logging.getLogger("microvm")


class SnapshotType(Enum):
    """Supported snapshot types."""

    FULL = "Full"
    DIFF = "Diff"

    def __repr__(self):
        cls_name = self.__class__.__name__
        return f"{cls_name}.{self.name}"


def hardlink_or_copy(src, dst):
    """If src and dst are in the same device, hardlink. Otherwise, copy."""
    dst.touch(exist_ok=False)
    if dst.stat().st_dev == src.stat().st_dev:
        dst.unlink()
        dst.hardlink_to(src)
    else:
        shutil.copyfile(src, dst)


@dataclass(frozen=True, repr=True)
class Snapshot:
    """A Firecracker snapshot"""

    vmstate: Path
    mem: Path
    net_ifaces: list
    disks: dict
    ssh_key: Path
    snapshot_type: SnapshotType

    @property
    def is_diff(self) -> bool:
        """Is this a DIFF snapshot?"""
        return self.snapshot_type == SnapshotType.DIFF

    def rebase_snapshot(self, base, use_snapshot_editor=False):
        """Rebases current incremental snapshot onto a specified base layer."""
        if not self.is_diff:
            raise ValueError("Can only rebase DIFF snapshots")
        if use_snapshot_editor:
            build_tools.run_snap_editor_rebase(base.mem, self.mem)
        else:
            build_tools.run_rebase_snap_bin(base.mem, self.mem)

        new_args = self.__dict__ | {"mem": base.mem}
        return Snapshot(**new_args)

    def copy_to_chroot(self, chroot) -> "Snapshot":
        """
        Move all the snapshot files into the microvm jail.
        Use different names so a snapshot doesn't overwrite our original snapshot.
        """
        mem_src = chroot / self.mem.with_suffix(".src").name
        hardlink_or_copy(self.mem, mem_src)
        vmstate_src = chroot / self.vmstate.with_suffix(".src").name
        hardlink_or_copy(self.vmstate, vmstate_src)

        return Snapshot(
            vmstate=vmstate_src,
            mem=mem_src,
            net_ifaces=self.net_ifaces,
            disks=self.disks,
            ssh_key=self.ssh_key,
            snapshot_type=self.snapshot_type,
        )

    @classmethod
    # TBD when Python 3.11: -> Self
    def load_from(cls, src: Path) -> "Snapshot":
        """Load a snapshot saved with `save_to`"""
        snap_json = src / "snapshot.json"
        obj = json.loads(snap_json.read_text())
        return cls(
            vmstate=src / obj["vmstate"],
            mem=src / obj["mem"],
            net_ifaces=[net_tools.NetIfaceConfig(**d) for d in obj["net_ifaces"]],
            disks={dsk: src / p for dsk, p in obj["disks"].items()},
            ssh_key=src / obj["ssh_key"],
            snapshot_type=SnapshotType(obj["snapshot_type"]),
        )

    def save_to(self, dst: Path):
        """Serialize snapshot details to `dst`

        Deserialize the snapshot with `load_from`
        """
        for path in [self.vmstate, self.mem, self.ssh_key]:
            new_path = dst / path.name
            hardlink_or_copy(path, new_path)
        new_disks = {}
        for disk_id, path in self.disks.items():
            new_path = dst / path.name
            hardlink_or_copy(path, new_path)
            new_disks[disk_id] = new_path.name
        obj = {
            "vmstate": self.vmstate.name,
            "mem": self.mem.name,
            "net_ifaces": [x.__dict__ for x in self.net_ifaces],
            "disks": new_disks,
            "ssh_key": self.ssh_key.name,
            "snapshot_type": self.snapshot_type.value,
        }
        snap_json = dst / "snapshot.json"
        snap_json.write_text(json.dumps(obj))

    def delete(self):
        """Delete the backing files from disk."""
        self.mem.unlink()
        self.vmstate.unlink()


class HugePagesConfig(str, Enum):
    """Enum describing the huge pages configurations supported Firecracker"""

    NONE = "None"
    HUGETLBFS_2MB = "2M"


# pylint: disable=R0904
class Microvm:
    """Class to represent a Firecracker microvm.

    A microvm is described by a unique identifier, a path to all the resources
    it needs in order to be able to start and the binaries used to spawn it.
    Besides keeping track of microvm resources and exposing microvm API
    methods, `spawn()` and `kill()` can be used to start/end the microvm
    process.
    """

    def __init__(
        self,
        microvm_id: str,
        fc_binary_path: Path,
        jailer_binary_path: Path,
        netns: net_tools.NetNs,
        monitor_memory: bool = True,
        jailer_kwargs: Optional[dict] = None,
        numa_node=None,
    ):
        """Set up microVM attributes, paths, and data structures."""
        # pylint: disable=too-many-statements
        # Unique identifier for this machine.
        assert microvm_id is not None
        self._microvm_id = microvm_id

        self.kernel_file = None
        self.rootfs_file = None
        self.ssh_key = None
        self.initrd_file = None
        self.boot_args = None

        self.fc_binary_path = Path(fc_binary_path)
        assert fc_binary_path.exists()
        self.jailer_binary_path = Path(jailer_binary_path)
        assert jailer_binary_path.exists()

        jailer_kwargs = jailer_kwargs or {}
        self.netns = netns
        # Create the jailer context associated with this microvm.
        self.jailer = JailerContext(
            jailer_id=self._microvm_id,
            exec_file=self.fc_binary_path,
            netns=netns,
            new_pid_ns=True,
            **jailer_kwargs,
        )

        # Copy the /etc/localtime file in the jailer root
        self.jailer.jailed_path("/etc/localtime", subdir="etc")

        self._screen_pid = None

        self.time_api_requests = global_props.host_linux_version != "6.1"
        # disable the HTTP API timings as they cause a lot of false positives
        if int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", 1)) > 1:
            self.time_api_requests = False

        self.monitors = []
        self.memory_monitor = None
        if monitor_memory:
            self.memory_monitor = MemoryMonitor(self)
            self.monitors.append(self.memory_monitor)

        self.api = None
        self.log_file = None
        self.metrics_file = None
        self._spawned = False
        self._killed = False

        # device dictionaries
        self.iface = {}
        self.disks = {}
        self.disks_vhost_user = {}
        self.vcpus_count = None
        self.mem_size_bytes = None

        self._numa_node = numa_node

        # MMDS content from file
        self.metadata_file = None

        self.help = MicrovmHelpers(self)

    def __repr__(self):
        return f"<Microvm id={self.id}>"

    def mark_killed(self):
        """
        Marks this `Microvm` as killed, meaning test tear down should not try to kill it

        raises an exception if the Firecracker process managing this VM is not actually dead
        """
        if self.firecracker_pid is not None:
            utils.wait_process_termination(self.firecracker_pid)

        self._killed = True

    def kill(self):
        """All clean up associated with this microVM should go here."""
        # pylint: disable=subprocess-run-check
        # if it was already killed, return
        if self._killed:
            return

        # Stop any registered monitors
        for monitor in self.monitors:
            monitor.stop()

        # We start with vhost-user backends,
        # because if we stop Firecracker first, the backend will want
        # to exit as well and this will cause a race condition.
        for backend in self.disks_vhost_user.values():
            backend.kill()
        self.disks_vhost_user.clear()

        assert (
            "Shutting down VM after intercepting signal" not in self.log_data
        ), self.log_data

        try:
            if self.firecracker_pid:
                os.kill(self.firecracker_pid, signal.SIGKILL)

            if self.screen_pid:
                os.kill(self.screen_pid, signal.SIGKILL)
        except:
            LOG.error(self.log_data)
            raise

        # if microvm was spawned then check if it gets killed
        if self._spawned:
            # Wait until the Firecracker process is actually dead
            utils.wait_process_termination(self.firecracker_pid)

            # The following logic guards us against the case where `firecracker_pid` for some
            # reason is the wrong PID, e.g. this is a regression test for
            # https://github.com/firecracker-microvm/firecracker/pull/4442/commits/d63eb7a65ffaaae0409d15ed55d99ecbd29bc572

            # filter ps results for the jailer's unique id
            _, stdout, stderr = utils.check_output(
                f"ps aux | grep {self.jailer.jailer_id}"
            )
            # make sure firecracker was killed
            assert (
                stderr == "" and "firecracker" not in stdout
            ), f"Firecracker reported its pid {self.firecracker_pid}, which was killed, but there still exist processes using the supposedly dead Firecracker's jailer_id: {stdout}"

        # Mark the microVM as not spawned, so we avoid trying to kill twice.
        self._spawned = False
        self._killed = True

        if self.time_api_requests:
            self._validate_api_response_times()

        if self.memory_monitor:
            self.memory_monitor.check_samples()

    def _validate_api_response_times(self):
        """
        Parses the firecracker logs for information regarding api server request processing times, and asserts they
        are within acceptable bounds.
        """
        # Log messages are either
        # 2023-06-16T07:45:41.767987318 [fc44b23e-ce47-4635-9549-5779a6bd9cee:fc_api] The API server received a Get request on "/mmds".
        # or
        # 2023-06-16T07:47:31.204704732 [2f2427c7-e4de-4226-90e6-e3556402be84:fc_api] The API server received a Put request on "/actions" with body "{\"action_type\": \"InstanceStart\"}".
        api_request_regex = re.compile(
            r"\] The API server received a (?P<method>\w+) request on \"(?P<url>(/(\w|-)*)+)\"( with body (?P<body>.*))?\."
        )
        api_request_times_regex = re.compile(
            r"\] Total previous API call duration: (?P<execution_time>\d+) us.$"
        )

        # Note: Processing of api requests is synchronous, so these messages cannot be torn by concurrency effects
        log_lines = self.log_data.split("\n")

        ApiCall = namedtuple("ApiCall", "method url body")

        current_call = None

        for log_line in log_lines:
            match = api_request_regex.search(log_line)

            if match:
                if current_call is not None:
                    raise Exception(
                        f"API call duration log entry for {current_call.method} {current_call.url} with body {current_call.body} is missing!"
                    )

                current_call = ApiCall(
                    match.group("method"), match.group("url"), match.group("body")
                )

            match = api_request_times_regex.search(log_line)

            if match:
                if current_call is None:
                    raise Exception(
                        "Got API call duration log entry before request entry"
                    )

                if current_call.url != "/snapshot/create":
                    exec_time = float(match.group("execution_time")) / 1000.0

                    assert (
                        exec_time <= MAX_API_CALL_DURATION_MS
                    ), f"{current_call.method} {current_call.url} API call exceeded maximum duration: {exec_time} ms. Body: {current_call.body}"

                current_call = None

    @property
    def firecracker_version(self):
        """Return the version of the Firecracker executable."""
        _, stdout, _ = utils.check_output(f"{self.fc_binary_path} --version")
        return re.match(r"^Firecracker v(.+)", stdout.partition("\n")[0]).group(1)

    @property
    def path(self):
        """Return the path on disk used that represents this microVM."""
        return self.jailer.chroot_base_with_id()

    # some functions use this
    fsfiles = path

    @property
    def id(self):
        """Return the unique identifier of this microVM."""
        return self._microvm_id

    @property
    def log_data(self):
        """Return the log data."""
        if self.log_file is None:
            return ""
        return self.log_file.read_text()

    @property
    def console_data(self):
        """Return the output of microVM's console"""
        if self.screen_log is None:
            return None
        return Path(self.screen_log).read_text(encoding="utf-8")

    @property
    def state(self):
        """Get the InstanceInfo property and return the state field."""
        return self.api.describe.get().json()["state"]

    @property
    def firecracker_pid(self):
        """Return Firecracker's PID

        Reads the pid from a file created by jailer.
        """
        if not self._spawned:
            return None
        # Read the PID stored inside the file.
        return int(self.jailer.pid_file.read_text(encoding="ascii"))

    @property
    def dimensions(self):
        """Gets a default set of cloudwatch dimensions describing the configuration of this microvm"""
        return {
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": f"linux-{global_props.host_linux_version}",
            "guest_kernel": self.kernel_file.stem[2:],
            "rootfs": self.rootfs_file.name,
            "vcpus": str(self.vcpus_count),
            "guest_memory": f"{self.mem_size_bytes / (1024 * 1024)}MB",
        }

    @property
    def guest_kernel_version(self):
        """Get the guest kernel version from the filename

        It won't work if the file name does not like name-X.Y.Z
        """
        splits = self.kernel_file.name.split("-")
        if len(splits) < 2:
            return None
        return tuple(int(x) for x in splits[1].split("."))

    def get_metrics(self):
        """Return iterator to metric data points written by FC"""
        with self.metrics_file.open() as fd:
            for line in fd:
                if not line.endswith("}\n"):
                    LOG.warning("Line is not a proper JSON object. Partial write?")
                    continue
                yield json.loads(line)

    def get_all_metrics(self):
        """Return all metric data points written by FC."""
        return list(self.get_metrics())

    def flush_metrics(self):
        """Flush the microvm metrics and get the latest datapoint"""
        self.api.actions.put(action_type="FlushMetrics")
        # get the latest metrics
        return self.get_all_metrics()[-1]

    def create_jailed_resource(self, path):
        """Create a hard link to some resource inside this microvm."""
        return self.jailer.jailed_path(path, create=True)

    def get_jailed_resource(self, path):
        """Get the relative jailed path to a resource."""
        return self.jailer.jailed_path(path, create=False)

    def chroot(self):
        """Get the chroot of this microVM."""
        return self.jailer.chroot_path()

    @property
    def screen_session(self):
        """The screen session name

        The id of this microVM, which should be unique.
        """
        return self.id

    @property
    def screen_log(self):
        """Get the screen log file."""
        return f"/tmp/screen-{self.screen_session}.log"

    @property
    def screen_pid(self) -> Optional[int]:
        """Get the screen PID."""
        if self._screen_pid:
            return int(self._screen_pid)
        return None

    def pin_vmm(self, cpu_id: int) -> bool:
        """Pin the firecracker process VMM thread to a cpu list."""
        if self.firecracker_pid:
            for thread_name, thread_pids in utils.get_threads(
                self.firecracker_pid
            ).items():
                # the firecracker thread should start with firecracker...
                if thread_name.startswith("firecracker"):
                    for pid in thread_pids:
                        utils.set_cpu_affinity(pid, [cpu_id])
                return True
        return False

    def pin_vcpu(self, vcpu_id: int, cpu_id: int):
        """Pin the firecracker vcpu thread to a cpu list."""
        if self.firecracker_pid:
            for thread in utils.get_threads(self.firecracker_pid)[f"fc_vcpu {vcpu_id}"]:
                utils.set_cpu_affinity(thread, [cpu_id])
            return True
        return False

    def pin_api(self, cpu_id: int):
        """Pin the firecracker process API server thread to a cpu list."""
        if self.firecracker_pid:
            for thread in utils.get_threads(self.firecracker_pid)["fc_api"]:
                utils.set_cpu_affinity(thread, [cpu_id])
            return True
        return False

    def pin_threads(self, first_cpu):
        """
        Pins all microvm threads (VMM, API and vCPUs) to consecutive physical cpu core, starting with "first_cpu"

        Return next "free" cpu core.
        """
        for vcpu, pcpu in enumerate(range(first_cpu, first_cpu + self.vcpus_count)):
            assert self.pin_vcpu(
                vcpu, pcpu
            ), f"Failed to pin fc_vcpu {vcpu} thread to core {pcpu}."
        # The cores first_cpu,...,first_cpu + self.vcpus_count - 1 are assigned to the individual vCPU threads,
        # So the remaining two threads (VMM and API) get first_cpu + self.vcpus_count
        # and first_cpu + self.vcpus_count + 1
        assert self.pin_vmm(
            first_cpu + self.vcpus_count
        ), "Failed to pin firecracker thread."
        assert self.pin_api(
            first_cpu + self.vcpus_count + 1
        ), "Failed to pin fc_api thread."

        return first_cpu + self.vcpus_count + 2

    def spawn(
        self,
        log_file="fc.log",
        log_level="Debug",
        log_show_level=False,
        log_show_origin=False,
        metrics_path="fc.ndjson",
        emit_metrics: bool = False,
    ):
        """Start a microVM as a daemon or in a screen session."""
        # pylint: disable=subprocess-run-check
        # pylint: disable=too-many-branches
        self.jailer.setup()
        self.api = Api(self.jailer.api_socket_path())

        if log_file is not None:
            self.log_file = Path(self.path) / log_file
            self.log_file.touch()
            self.create_jailed_resource(self.log_file)
            # The default value for `level`, when configuring the logger via cmd
            # line, is `Info`. We set the level to `Debug` to also have the boot
            # time printed in the log.
            self.jailer.extra_args.update({"log-path": log_file, "level": log_level})
            if log_show_level:
                self.jailer.extra_args["show-level"] = None
            if log_show_origin:
                self.jailer.extra_args["show-log-origin"] = None

        if metrics_path is not None:
            self.metrics_file = Path(self.path) / metrics_path
            self.metrics_file.touch()
            self.create_jailed_resource(self.metrics_file)
            self.jailer.extra_args.update({"metrics-path": self.metrics_file.name})
        else:
            assert not emit_metrics

        if self.metadata_file:
            if os.path.exists(self.metadata_file):
                LOG.debug("metadata file exists, adding as a jailed resource")
                self.create_jailed_resource(self.metadata_file)
            self.jailer.extra_args.update(
                {"metadata": os.path.basename(self.metadata_file)}
            )

        if log_level != "Debug":
            # Checking the timings requires DEBUG level log messages
            self.time_api_requests = False

        cmd = [str(self.jailer_binary_path)] + self.jailer.construct_param_list()
        if self._numa_node is not None:
            node = str(self._numa_node)
            cmd = ["numactl", "-N", node, "-m", node] + cmd

        # When the daemonize flag is on, we want to clone-exec into the
        # jailer rather than executing it via spawning a shell.
        if self.jailer.daemonize:
            utils.check_output(cmd, shell=False)
        else:
            # Run Firecracker under screen. This is used when we want to access
            # the serial console. The file will collect the output from
            # 'screen'ed Firecracker.
            screen_pid = utils.start_screen_process(
                self.screen_log,
                self.screen_session,
                cmd[0],
                cmd[1:],
            )
            self._screen_pid = screen_pid

        self._spawned = True

        if emit_metrics:
            self.monitors.append(FCMetricsMonitor(self))

        # Wait for the jailer to create resources needed, and Firecracker to
        # create its API socket.
        # We expect the jailer to start within 80 ms. However, we wait for
        # 1 sec since we are rechecking the existence of the socket 5 times
        # and leave 0.2 delay between them.
        if "no-api" not in self.jailer.extra_args:
            self._wait_create()
        if self.log_file and log_level in ("Trace", "Debug", "Info"):
            self.check_log_message("Running Firecracker")

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def _wait_create(self):
        """Wait until the API socket and chroot folder are available."""
        os.stat(self.jailer.api_socket_path())

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def check_log_message(self, message):
        """Wait until `message` appears in logging output."""
        assert (
            message in self.log_data
        ), f'Message ("{message}") not found in log data ("{self.log_data}").'

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def get_exit_code(self):
        """Get exit code from logging output"""
        exit_msg_pattern = (
            r"Firecracker exiting (with error|successfully). exit_code=(\d+)"
        )
        match = re.search(exit_msg_pattern, self.log_data)
        if match:
            exit_code = int(match.group(2))
            return exit_code
        raise AssertionError(f"unable to find exit code from the log: {self.log_data}")

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def check_any_log_message(self, messages):
        """Wait until any message in `messages` appears in logging output."""
        for message in messages:
            if message in self.log_data:
                return
        raise AssertionError(
            f"`{messages}` were not found in this log: {self.log_data}"
        )

    def serial_input(self, input_string):
        """Send a string to the Firecracker serial console via screen."""
        input_cmd = f'screen -S {self.screen_session} -p 0 -X stuff "{input_string}"'
        return utils.check_output(input_cmd)

    def basic_config(
        self,
        vcpu_count: int = 2,
        smt: bool = None,
        mem_size_mib: int = 256,
        add_root_device: bool = True,
        boot_args: str = None,
        use_initrd: bool = False,
        track_dirty_pages: bool = False,
        huge_pages: HugePagesConfig = None,
        rootfs_io_engine=None,
        cpu_template: Optional[str] = None,
        enable_entropy_device=False,
    ):
        """Shortcut for quickly configuring a microVM.

        It handles:
        - CPU and memory.
        - Kernel image (will load the one in the microVM allocated path).
        - Root File System (will use the one in the microVM allocated path).
        - Does not start the microvm.

        The function checks the response status code and asserts that
        the response is within the interval [200, 300).

        If boot_args is None, the default boot_args in Firecracker is
            reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0
            i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd

        Reference: file:../../src/vmm/src/vmm_config/boot_source.rs::DEFAULT_KERNEL_CMDLINE
        """
        self.api.machine_config.put(
            vcpu_count=vcpu_count,
            smt=smt,
            mem_size_mib=mem_size_mib,
            track_dirty_pages=track_dirty_pages,
            cpu_template=cpu_template,
            huge_pages=huge_pages,
        )
        self.vcpus_count = vcpu_count
        self.mem_size_bytes = mem_size_mib * 2**20

        if self.memory_monitor:
            self.memory_monitor.start()

        if boot_args is not None:
            self.boot_args = boot_args
        boot_source_args = {
            "kernel_image_path": self.create_jailed_resource(self.kernel_file),
            "boot_args": self.boot_args,
        }

        if use_initrd and self.initrd_file is not None:
            boot_source_args.update(
                initrd_path=self.create_jailed_resource(self.initrd_file)
            )

        self.api.boot.put(**boot_source_args)

        if add_root_device and self.rootfs_file is not None:
            read_only = self.rootfs_file.suffix == ".squashfs"

            # Add the root file system
            self.add_drive(
                drive_id="rootfs",
                path_on_host=self.rootfs_file,
                is_root_device=True,
                is_read_only=read_only,
                io_engine=rootfs_io_engine,
            )

        if enable_entropy_device:
            self.enable_entropy_device()

    def add_drive(
        self,
        drive_id,
        path_on_host,
        is_root_device=False,
        is_read_only=False,
        partuuid=None,
        cache_type=None,
        io_engine=None,
    ):
        """Add a block device."""

        path_on_jail = self.create_jailed_resource(path_on_host)
        self.api.drive.put(
            drive_id=drive_id,
            path_on_host=path_on_jail,
            is_root_device=is_root_device,
            is_read_only=is_read_only,
            partuuid=partuuid,
            cache_type=cache_type,
            io_engine=io_engine,
        )
        self.disks[drive_id] = path_on_host

    def add_vhost_user_drive(
        self,
        drive_id,
        path_on_host,
        partuuid=None,
        is_root_device=False,
        is_read_only=False,
        cache_type=None,
        backend_type=VhostUserBlkBackendType.CROSVM,
    ):
        """Add a vhost-user block device."""

        # It is possible that the user adds another drive
        # with the same ID. In that case, we should clean
        # the previous backend up first.
        prev = self.disks_vhost_user.pop(drive_id, None)
        if prev:
            prev.kill()

        backend = VhostUserBlkBackend.with_backend(
            backend_type, path_on_host, self.chroot(), drive_id, is_read_only
        )

        socket = backend.spawn(self.jailer.uid, self.jailer.gid)

        self.api.drive.put(
            drive_id=drive_id,
            socket=socket,
            partuuid=partuuid,
            is_root_device=is_root_device,
            cache_type=cache_type,
        )

        self.disks_vhost_user[drive_id] = backend

    def patch_drive(self, drive_id, file=None):
        """Modify/patch an existing block device."""
        if file:
            self.api.drive.patch(
                drive_id=drive_id,
                path_on_host=self.create_jailed_resource(file.path),
            )
            self.disks[drive_id] = Path(file.path)
        else:
            self.api.drive.patch(drive_id=drive_id)

    def add_net_iface(self, iface=None, api=True, **kwargs):
        """Add a network interface"""
        if iface is None:
            iface = net_tools.NetIfaceConfig.with_id(len(self.iface))
        tap = self.netns.add_tap(
            iface.tap_name, ip=f"{iface.host_ip}/{iface.netmask_len}"
        )
        self.iface[iface.dev_name] = {
            "iface": iface,
            "tap": tap,
        }

        # If api, call it... there may be cases when we don't want it, for
        # example during restore
        if api:
            self.api.network.put(
                iface_id=iface.dev_name,
                host_dev_name=iface.tap_name,
                guest_mac=iface.guest_mac,
                **kwargs,
            )

        return iface

    def start(self):
        """Start the microvm.

        This function validates that the microvm boot succeeds.
        """
        # Check that the VM has not started yet
        assert self.state == "Not started"

        self.api.actions.put(action_type="InstanceStart")

        # Check that the VM has started
        assert self.state == "Running"

    def pause(self):
        """Pauses the microVM"""
        self.api.vm.patch(state="Paused")

    def resume(self):
        """Resume the microVM"""
        self.api.vm.patch(state="Resumed")

    def make_snapshot(
        self,
        snapshot_type: SnapshotType | str,
        *,
        mem_path: str = "mem",
        vmstate_path="vmstate",
    ):
        """Create a Snapshot object from a microvm.

        The snapshot's memory and vstate files will be saved at the specified paths
        relative to the Microvm's chroot.

        It pauses the microvm before taking the snapshot.
        """
        snapshot_type = SnapshotType(snapshot_type)
        self.pause()
        self.api.snapshot_create.put(
            mem_file_path=str(mem_path),
            snapshot_path=str(vmstate_path),
            snapshot_type=snapshot_type.value,
        )
        root = Path(self.chroot())
        return Snapshot(
            vmstate=root / vmstate_path,
            mem=root / mem_path,
            disks=self.disks,
            net_ifaces=[x["iface"] for ifname, x in self.iface.items()],
            ssh_key=self.ssh_key,
            snapshot_type=snapshot_type,
        )

    def snapshot_diff(self, *, mem_path: str = "mem", vmstate_path="vmstate"):
        """Make a Diff snapshot"""
        return self.make_snapshot("Diff", mem_path=mem_path, vmstate_path=vmstate_path)

    def snapshot_full(self, *, mem_path: str = "mem", vmstate_path="vmstate"):
        """Make a Full snapshot"""
        return self.make_snapshot("Full", mem_path=mem_path, vmstate_path=vmstate_path)

    def restore_from_snapshot(
        self,
        snapshot: Snapshot,
        resume: bool = False,
        uffd_path: Path = None,
    ):
        """Restore a snapshot"""
        jailed_snapshot = snapshot.copy_to_chroot(Path(self.chroot()))
        jailed_mem = Path("/") / jailed_snapshot.mem.name
        jailed_vmstate = Path("/") / jailed_snapshot.vmstate.name

        snapshot_disks = [v for k, v in snapshot.disks.items()]
        assert len(snapshot_disks) > 0, "Snapshot requires at least one disk."
        jailed_disks = []
        for disk in snapshot_disks:
            jailed_disks.append(self.create_jailed_resource(disk))
        self.disks = snapshot.disks
        self.ssh_key = snapshot.ssh_key

        # Create network interfaces.
        for iface in snapshot.net_ifaces:
            self.add_net_iface(iface, api=False)

        mem_backend = {"backend_type": "File", "backend_path": str(jailed_mem)}
        if uffd_path is not None:
            mem_backend = {"backend_type": "Uffd", "backend_path": str(uffd_path)}

        self.api.snapshot_load.put(
            mem_backend=mem_backend,
            snapshot_path=str(jailed_vmstate),
            enable_diff_snapshots=snapshot.is_diff,
            resume_vm=resume,
        )
        return jailed_snapshot

    def enable_entropy_device(self):
        """Enable entropy device for microVM"""
        self.api.entropy.put()

    def restore_from_path(self, snap_dir: Path, **kwargs):
        """Restore snapshot from a path"""
        return self.restore_from_snapshot(Snapshot.load_from(snap_dir), **kwargs)

    @lru_cache
    def ssh_iface(self, iface_idx=0):
        """Return a cached SSH connection on a given interface id."""
        guest_ip = list(self.iface.values())[iface_idx]["iface"].guest_ip
        self.ssh_key = Path(self.ssh_key)
        return net_tools.SSHConnection(
            netns=self.netns.id,
            ssh_key=self.ssh_key,
            user="root",
            host=guest_ip,
        )

    @property
    def ssh(self):
        """Return a cached SSH connection on the 1st interface"""
        return self.ssh_iface(0)

    @property
    def thread_backtraces(self):
        """Return backtraces of all threads"""
        backtraces = []
        for thread_name, thread_pids in utils.get_threads(self.firecracker_pid).items():
            for pid in thread_pids:
                backtraces.append(
                    f"{thread_name} ({pid=}):\n"
                    f"{utils.check_output(f'cat /proc/{pid}/stack').stdout}"
                )
        return "\n".join(backtraces)

    def wait_for_up(self, timeout=10):
        """Wait for guest running inside the microVM to come up and respond.

        :param timeout: seconds to wait.
        """
        try:
            rc, stdout, stderr = self.ssh.run("true", timeout)
        except subprocess.TimeoutExpired:
            print(
                f"Remote command did not respond within {timeout}s\n\n"
                f"Firecracker logs:\n{self.log_data}\n"
                f"Thread backtraces:\n{self.thread_backtraces}"
            )
            raise
        assert rc == 0, (
            f"Remote command exited with non-0 status code\n\n"
            f"{rc=}\n{stdout=}\n{stderr=}\n\n"
            f"Firecracker logs:\n{self.log_data}\n"
            f"Thread backtraces:\n{self.thread_backtraces}"
        )


class MicroVMFactory:
    """MicroVM factory"""

    def __init__(self, fc_binary_path: Path, jailer_binary_path: Path, **kwargs):
        self.vms = []
        self.fc_binary_path = Path(fc_binary_path)
        self.jailer_binary_path = Path(jailer_binary_path)
        self.kwargs = kwargs

    def build(self, kernel=None, rootfs=None, **kwargs):
        """Build a microvm"""
        kwargs = self.kwargs | kwargs
        microvm_id = kwargs.pop("microvm_id", str(uuid.uuid4()))
        vm = Microvm(
            microvm_id=microvm_id,
            fc_binary_path=kwargs.pop("fc_binary_path", self.fc_binary_path),
            jailer_binary_path=kwargs.pop(
                "jailer_binary_path", self.jailer_binary_path
            ),
            netns=kwargs.pop("netns", net_tools.NetNs(microvm_id)),
            **kwargs,
        )
        vm.netns.setup()
        self.vms.append(vm)
        if kernel is not None:
            vm.kernel_file = kernel
        if rootfs is not None:
            ssh_key = rootfs.with_suffix(".id_rsa")
            # copy only iff not a read-only rootfs
            rootfs_path = rootfs
            if rootfs_path.suffix != ".squashfs":
                rootfs_path = Path(vm.path) / rootfs.name
                shutil.copyfile(rootfs, rootfs_path)
            vm.rootfs_file = rootfs_path
            vm.ssh_key = ssh_key
        return vm

    def kill(self):
        """Clean up all built VMs"""
        for vm in self.vms:
            vm.kill()
            vm.jailer.cleanup()
            chroot_base_with_id = vm.jailer.chroot_base_with_id()
            if len(vm.jailer.jailer_id) > 0 and chroot_base_with_id.exists():
                shutil.rmtree(chroot_base_with_id)
            vm.netns.cleanup()

        self.vms.clear()


class Serial:
    """Class for serial console communication with a Microvm."""

    RX_TIMEOUT_S = 60

    def __init__(self, vm):
        """Initialize a new Serial object."""
        self._poller = None
        self._vm = vm

    def open(self):
        """Open a serial connection."""
        # Open the screen log file.
        if self._poller is not None:
            # serial already opened
            return

        attempt = 0
        while not Path(self._vm.screen_log).exists() and attempt < 5:
            time.sleep(0.2)
            attempt += 1

        screen_log_fd = os.open(self._vm.screen_log, os.O_RDONLY)
        self._poller = select.poll()
        self._poller.register(screen_log_fd, select.POLLIN | select.POLLHUP)

    def tx(self, input_string, end="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Send a string terminated by an end token (defaulting to "\n")."""
        self._vm.serial_input(input_string + end)

    def rx_char(self):
        """Read a single character."""
        result = self._poller.poll(0.1)

        for fd, flag in result:
            if flag & select.POLLHUP:
                assert False, "Oh! The console vanished before test completed."

            if flag & select.POLLIN:
                output_char = str(os.read(fd, 1), encoding="utf-8", errors="ignore")
                return output_char

        return ""

    def rx(self, token="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Read a string delimited by an end token (defaults to "\n")."""
        rx_str = ""
        start = time.time()
        while True:
            rx_str += self.rx_char()
            if rx_str.endswith(token):
                break
            if (time.time() - start) >= self.RX_TIMEOUT_S:
                self._vm.kill()
                assert False

        return rx_str
