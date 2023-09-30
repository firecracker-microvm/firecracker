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
import time
import uuid
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional

from retry import retry

import host_tools.cargo_build as build_tools
import host_tools.network as net_tools
from framework import utils
from framework.artifacts import NetIfaceConfig
from framework.defs import FC_PID_FILE_NAME, MAX_API_CALL_DURATION_MS
from framework.http_api import Api
from framework.jailer import JailerContext
from framework.microvm_helpers import MicrovmHelpers
from framework.properties import global_props
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

    @classmethod
    # TBD when Python 3.11: -> Self
    def load_from(cls, src: Path) -> "Snapshot":
        """Load a snapshot saved with `save_to`"""
        snap_json = src / "snapshot.json"
        obj = json.loads(snap_json.read_text())
        return cls(
            vmstate=src / obj["vmstate"],
            mem=src / obj["mem"],
            net_ifaces=[NetIfaceConfig(**d) for d in obj["net_ifaces"]],
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
        resource_path,
        fc_binary_path,
        jailer_binary_path,
        microvm_id=None,
        bin_cloner_path=None,
        monitor_memory=True,
    ):
        """Set up microVM attributes, paths, and data structures."""
        # pylint: disable=too-many-statements
        # Unique identifier for this machine.
        if microvm_id is None:
            microvm_id = str(uuid.uuid4())
        self._microvm_id = microvm_id

        # Compose the paths to the resources specific to this microvm.
        self._path = os.path.join(resource_path, microvm_id)
        os.makedirs(self._path, exist_ok=True)
        self.kernel_file = None
        self.rootfs_file = None
        self.ssh_key = None
        self.initrd_file = None
        self.boot_args = None

        self._fc_binary_path = str(fc_binary_path)
        assert fc_binary_path.exists()
        self._jailer_binary_path = str(jailer_binary_path)
        assert jailer_binary_path.exists()

        # Create the jailer context associated with this microvm.
        self.jailer = JailerContext(
            jailer_id=self._microvm_id,
            exec_file=self._fc_binary_path,
        )
        self.jailer_clone_pid = None

        # Copy the /etc/localtime file in the jailer root
        self.jailer.jailed_path("/etc/localtime", subdir="etc")

        # Initialize the logging subsystem.
        self._screen_pid = None

        self.time_api_requests = global_props.host_linux_version != "6.1"
        # disable the HTTP API timings as they cause a lot of false positives
        if int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", 1)) > 1:
            self.time_api_requests = False

        self.memory_monitor = None
        if monitor_memory:
            self.memory_monitor = MemoryMonitor(self)

        self.api = None
        self.log_file = None
        self.metrics_file = None

        # device dictionaries
        self.iface = {}
        self.disks = {}
        self.vcpus_count = None
        self.mem_size_bytes = None

        # External clone/exec tool, because Python can't into clone
        self.bin_cloner_path = bin_cloner_path

        # Flag checked in destructor to see abnormal signal-induced crashes.
        self.expect_kill_by_signal = False

        # MMDS content from file
        self.metadata_file = None

        self.help = MicrovmHelpers(self)

    def __repr__(self):
        return f"<Microvm id={self.id}>"

    def kill(self):
        """All clean up associated with this microVM should go here."""
        # pylint: disable=subprocess-run-check

        if (
            self.expect_kill_by_signal is False
            and "Shutting down VM after intercepting signal" in self.log_data
        ):
            # Too late to assert at this point, pytest will still report the
            # test as passed. BUT we can dump full logs for debugging,
            # as well as an intentional eye-sore in the test report.
            LOG.error(self.log_data)

        if self.jailer.daemonize:
            if self.jailer_clone_pid:
                utils.run_cmd(
                    "kill -9 {}".format(self.jailer_clone_pid), ignore_return_code=True
                )
        else:
            # Killing screen will send SIGHUP to underlying Firecracker.
            # Needed to avoid false positives in case kill() is called again.
            self.expect_kill_by_signal = True
            utils.run_cmd("kill -9 {} || true".format(self.screen_pid))

        if self.time_api_requests:
            self._validate_api_response_times()

        # Check if Firecracker was launched by the jailer in a new pid ns.
        if self.jailer.new_pid_ns:
            # We need to explicitly kill the Firecracker pid, since it's
            # different from the jailer pid that was previously killed.
            utils.run_cmd(f"kill -9 {self.pid_in_new_ns}", ignore_return_code=True)

        if self.memory_monitor:
            if self.memory_monitor.is_alive():
                self.memory_monitor.signal_stop()
                self.memory_monitor.join(timeout=1)
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
        _, stdout, _ = utils.run_cmd(f"{self._fc_binary_path} --version")
        return re.match(r"^Firecracker v(.+)", stdout.partition("\n")[0]).group(1)

    @property
    def path(self):
        """Return the path on disk used that represents this microVM."""
        return self._path

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
    def state(self):
        """Get the InstanceInfo property and return the state field."""
        return self.api.describe.get().json()["state"]

    @property
    @retry(delay=0.1, tries=5, logger=None)
    def pid_in_new_ns(self):
        """Get the pid of the Firecracker process in the new namespace.

        Reads the pid from a file created by jailer with `--new-pid-ns` flag.
        """
        # Check if the pid file exists.
        pid_file_path = Path(f"{self.jailer.chroot_path()}/{FC_PID_FILE_NAME}")
        assert pid_file_path.exists()

        # Read the PID stored inside the file.
        return int(pid_file_path.read_text(encoding="ascii"))

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

    def flush_metrics(self):
        """Flush the microvm metrics and get the latest datapoint"""
        self.api.actions.put(action_type="FlushMetrics")
        # get the latest metrics
        return self.get_all_metrics()[-1]

    def get_all_metrics(self):
        """Return all metric data points written by FC."""
        return [json.loads(line) for line in self.metrics_file.read_text().splitlines()]

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
    def screen_pid(self):
        """Get the screen PID."""
        return self._screen_pid

    def pin_vmm(self, cpu_id: int) -> bool:
        """Pin the firecracker process VMM thread to a cpu list."""
        if self.jailer_clone_pid:
            for thread_name, thread_pids in utils.ProcessManager.get_threads(
                self.jailer_clone_pid
            ).items():
                # the firecracker thread should start with firecracker...
                if thread_name.startswith("firecracker"):
                    for pid in thread_pids:
                        utils.ProcessManager.set_cpu_affinity(pid, [cpu_id])
                return True
        return False

    def pin_vcpu(self, vcpu_id: int, cpu_id: int):
        """Pin the firecracker vcpu thread to a cpu list."""
        if self.jailer_clone_pid:
            for thread in utils.ProcessManager.get_threads(self.jailer_clone_pid)[
                f"fc_vcpu {vcpu_id}"
            ]:
                utils.ProcessManager.set_cpu_affinity(thread, [cpu_id])
            return True
        return False

    def pin_api(self, cpu_id: int):
        """Pin the firecracker process API server thread to a cpu list."""
        if self.jailer_clone_pid:
            for thread in utils.ProcessManager.get_threads(self.jailer_clone_pid)[
                "fc_api"
            ]:
                utils.ProcessManager.set_cpu_affinity(thread, [cpu_id])
            return True
        return False

    def spawn(
        self,
        log_file="fc.log",
        log_level="Debug",
        metrics_path="fc.ndjson",
    ):
        """Start a microVM as a daemon or in a screen session."""
        # pylint: disable=subprocess-run-check
        self.jailer.setup()
        self.api = Api(self.jailer.api_socket_path())

        if log_file is not None:
            self.log_file = Path(self.path) / log_file
            self.log_file.touch()
            self.create_jailed_resource(self.log_file)
            # The default value for `level`, when configuring the
            # logger via cmd line, is `Warning`. We set the level
            # to `Debug` to also have the boot time printed in fifo.
            self.jailer.extra_args.update({"log-path": log_file, "level": log_level})

        if metrics_path is not None:
            self.metrics_file = Path(self.path) / metrics_path
            self.metrics_file.touch()
            self.create_jailed_resource(self.metrics_file)
            self.jailer.extra_args.update({"metrics-path": self.metrics_file.name})

        if self.metadata_file:
            if os.path.exists(self.metadata_file):
                LOG.debug("metadata file exists, adding as a jailed resource")
                self.create_jailed_resource(self.metadata_file)
            self.jailer.extra_args.update(
                {"metadata": os.path.basename(self.metadata_file)}
            )

        jailer_param_list = self.jailer.construct_param_list()

        if log_level != "Debug":
            # Checking the timings requires DEBUG level log messages
            self.time_api_requests = False

        # When the daemonize flag is on, we want to clone-exec into the
        # jailer rather than executing it via spawning a shell. Going
        # forward, we'll probably switch to this method for running
        # Firecracker in general, because it represents the way it's meant
        # to be run by customers (together with CLONE_NEWPID flag).
        #
        # We have to use an external tool for CLONE_NEWPID, because
        # 1) Python doesn't provide os.clone() interface, and
        # 2) Python's ctypes libc interface appears to be broken, causing
        # our clone / exec to deadlock at some point.
        if self.jailer.daemonize:
            self.daemonize_jailer(jailer_param_list)
        else:
            # This file will collect any output from 'screen'ed Firecracker.
            screen_pid, binary_pid = utils.start_screen_process(
                self.screen_log,
                self.screen_session,
                self._jailer_binary_path,
                jailer_param_list,
            )
            self._screen_pid = screen_pid
            self.jailer_clone_pid = binary_pid

        # Wait for the jailer to create resources needed, and Firecracker to
        # create its API socket.
        # We expect the jailer to start within 80 ms. However, we wait for
        # 1 sec since we are rechecking the existence of the socket 5 times
        # and leave 0.2 delay between them.
        if "no-api" not in self.jailer.extra_args:
            self._wait_create()
        if self.log_file:
            self.check_log_message("Running Firecracker")

    @retry(delay=0.2, tries=5, logger=None)
    def _wait_create(self):
        """Wait until the API socket and chroot folder are available."""
        os.stat(self.jailer.api_socket_path())

    @retry(delay=0.2, tries=5, logger=None)
    def check_log_message(self, message):
        """Wait until `message` appears in logging output."""
        assert (
            message in self.log_data
        ), f'Message ("{message}") not found in log data ("{self.log_data}").'

    @retry(delay=0.2, tries=5, logger=None)
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
        return utils.run_cmd(input_cmd)

    def basic_config(
        self,
        vcpu_count: int = 2,
        smt: bool = None,
        mem_size_mib: int = 256,
        add_root_device: bool = True,
        boot_args: str = None,
        use_initrd: bool = False,
        track_dirty_pages: bool = False,
        rootfs_io_engine=None,
        cpu_template: Optional[str] = None,
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

    def daemonize_jailer(self, jailer_param_list):
        """Daemonize the jailer."""
        if self.bin_cloner_path and self.jailer.new_pid_ns is not True:
            cmd = (
                [self.bin_cloner_path] + [self._jailer_binary_path] + jailer_param_list
            )
            _p = utils.run_cmd(cmd)
            # Terrible hack to make the tests fail when starting the
            # jailer fails with a panic. This is needed because we can't
            # get the exit code of the jailer. In newpid_clone.c we are
            # not waiting for the process and we always return 0 if the
            # clone was successful (which in most cases will be) and we
            # don't do anything if the jailer was not started
            # successfully.
            if _p.stderr.strip():
                raise Exception(_p.stderr)
            self.jailer_clone_pid = int(_p.stdout.rstrip())
        else:
            # Fallback mechanism for when we offload PID namespacing
            # to the jailer.
            _pid = os.fork()
            if _pid == 0:
                os.execv(
                    self._jailer_binary_path,
                    [self._jailer_binary_path] + jailer_param_list,
                )
            self.jailer_clone_pid = _pid

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

    def patch_drive(self, drive_id, file):
        """Modify/patch an existing block device."""
        self.api.drive.patch(
            drive_id=drive_id,
            path_on_host=self.create_jailed_resource(file.path),
        )
        self.disks[drive_id] = Path(file.path)

    def add_net_iface(self, iface=None, api=True, **kwargs):
        """Add a network interface"""
        if iface is None:
            iface = NetIfaceConfig.with_id(len(self.iface))
        tap = net_tools.Tap(
            iface.tap_name, self.jailer.netns, ip=f"{iface.host_ip}/{iface.netmask}"
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
        self, snapshot_type: SnapshotType | str, target_version: str = None
    ):
        """Create a Snapshot object from a microvm.

        It pauses the microvm before taking the snapshot.
        """
        vmstate_path = "vmstate"
        mem_path = "mem"
        snapshot_type = SnapshotType(snapshot_type)
        self.pause()
        self.api.snapshot_create.put(
            mem_file_path=str(mem_path),
            snapshot_path=str(vmstate_path),
            snapshot_type=snapshot_type.value,
            version=target_version,
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

    def snapshot_diff(self, target_version: str = None):
        """Make a Diff snapshot"""
        return self.make_snapshot("Diff", target_version)

    def snapshot_full(self, target_version: str = None):
        """Make a Full snapshot"""
        return self.make_snapshot("Full", target_version)

    def restore_from_snapshot(
        self,
        snapshot: Snapshot,
        resume: bool = False,
        uffd_path: Path = None,
    ):
        """Restore a snapshot"""
        # Move all the snapshot files into the microvm jail.
        # Use different names so a snapshot doesn't overwrite our original snapshot.
        chroot = Path(self.chroot())
        mem_src = chroot / snapshot.mem.with_suffix(".src").name
        hardlink_or_copy(snapshot.mem, mem_src)
        vmstate_src = chroot / snapshot.vmstate.with_suffix(".src").name
        hardlink_or_copy(snapshot.vmstate, vmstate_src)
        jailed_mem = Path("/") / mem_src.name
        jailed_vmstate = Path("/") / vmstate_src.name

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
        return True

    def restore_from_path(self, snap_dir: Path, **kwargs):
        """Restore snapshot from a path"""
        return self.restore_from_snapshot(Snapshot.load_from(snap_dir), **kwargs)

    @lru_cache
    def ssh_iface(self, iface_idx=0):
        """Return a cached SSH connection on a given interface id."""
        guest_ip = list(self.iface.values())[iface_idx]["iface"].guest_ip
        self.ssh_key = Path(self.ssh_key)
        return net_tools.SSHConnection(
            netns_path=self.jailer.netns_file_path(),
            ssh_key=self.ssh_key,
            user="root",
            host=guest_ip,
        )

    @property
    def ssh(self):
        """Return a cached SSH connection on the 1st interface"""
        return self.ssh_iface(0)


class MicroVMFactory:
    """MicroVM factory"""

    def __init__(self, base_path, bin_cloner, fc_binary_path, jailer_binary_path):
        self.base_path = Path(base_path)
        self.bin_cloner_path = bin_cloner
        self.vms = []
        self.fc_binary_path = fc_binary_path
        self.jailer_binary_path = jailer_binary_path

    def build(self, kernel=None, rootfs=None, microvm_id=None, **kwargs):
        """Build a microvm"""
        vm = Microvm(
            resource_path=self.base_path,
            microvm_id=microvm_id or str(uuid.uuid4()),
            bin_cloner_path=self.bin_cloner_path,
            fc_binary_path=kwargs.pop("fc_binary_path", self.fc_binary_path),
            jailer_binary_path=kwargs.pop(
                "jailer_binary_path", self.jailer_binary_path
            ),
            **kwargs,
        )
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
            if len(vm.jailer.jailer_id) > 0:
                shutil.rmtree(vm.jailer.chroot_base_with_id())


class Serial:
    """Class for serial console communication with a Microvm."""

    RX_TIMEOUT_S = 20

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
