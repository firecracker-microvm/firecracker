# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Classes for working with microVMs.

This module defines `Microvm`, which can be used to create, test drive, and
destroy microvms.

# TODO

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
"""

import json
import logging
import os
import re
import select
import time

from retry import retry
from retry.api import retry_call

import host_tools.logging as log_tools
import host_tools.cpu_load as cpu_tools
import host_tools.memory as mem_tools
import host_tools.network as net_tools

import framework.utils as utils
from framework.defs import MICROVM_KERNEL_RELPATH, MICROVM_FSFILES_RELPATH
from framework.http import Session
from framework.jailer import JailerContext
from framework.resources import Actions, BootSource, Drive, Logger, MMDS, \
    MachineConfigure, Metrics, Network, Vm, Vsock, SnapshotCreate, SnapshotLoad

LOG = logging.getLogger("microvm")


# pylint: disable=R0904
class Microvm:
    """Class to represent a Firecracker microvm.

    A microvm is described by a unique identifier, a path to all the resources
    it needs in order to be able to start and the binaries used to spawn it.
    Besides keeping track of microvm resources and exposing microvm API
    methods, `spawn()` and `kill()` can be used to start/end the microvm
    process.
    """

    SCREEN_LOGFILE = "/tmp/screen.log"

    def __init__(
        self,
        resource_path,
        fc_binary_path,
        jailer_binary_path,
        microvm_id,
        monitor_memory=True,
        bin_cloner_path=None,
    ):
        """Set up microVM attributes, paths, and data structures."""
        # Unique identifier for this machine.
        self._microvm_id = microvm_id

        # Compose the paths to the resources specific to this microvm.
        self._path = os.path.join(resource_path, microvm_id)
        self._kernel_path = os.path.join(self._path, MICROVM_KERNEL_RELPATH)
        self._fsfiles_path = os.path.join(self._path, MICROVM_FSFILES_RELPATH)
        self._kernel_file = ''
        self._rootfs_file = ''
        self._initrd_file = ''

        # The binaries this microvm will use to start.
        self._fc_binary_path = fc_binary_path
        assert os.path.exists(self._fc_binary_path)
        self._jailer_binary_path = jailer_binary_path
        assert os.path.exists(self._jailer_binary_path)

        # Create the jailer context associated with this microvm.
        self._jailer = JailerContext(
            jailer_id=self._microvm_id,
            exec_file=self._fc_binary_path,
        )
        self.jailer_clone_pid = None

        # Copy the /etc/localtime file in the jailer root
        self.jailer.copy_into_root(
            "/etc/localtime", create_jail=True)

        # Now deal with the things specific to the api session used to
        # communicate with this machine.
        self._api_session = None
        self._api_socket = None

        # Session name is composed of the last part of the temporary path
        # allocated by the current test session and the unique id of this
        # microVM. It should be unique.
        self._session_name = os.path.basename(os.path.normpath(
            resource_path
        )) + self._microvm_id

        # nice-to-have: Put these in a dictionary.
        self.actions = None
        self.boot = None
        self.drive = None
        self.logger = None
        self.metrics = None
        self.mmds = None
        self.network = None
        self.machine_cfg = None
        self.vm = None
        self.vsock = None
        self.snapshot_create = None
        self.snapshot_load = None

        # Initialize the logging subsystem.
        self.logging_thread = None
        self._log_data = ""

        # The ssh config dictionary is populated with information about how
        # to connect to a microVM that has ssh capability. The path of the
        # private key is populated by microvms with ssh capabilities and the
        # hostname is set from the MAC address used to configure the microVM.
        self._ssh_config = {
            'username': 'root',
            'netns_file_path': self._jailer.netns_file_path()
        }

        # Deal with memory monitoring.
        if monitor_memory:
            self._memory_monitor = mem_tools.MemoryMonitor()
        else:
            self._memory_monitor = None

        # Cpu load monitoring has to be explicitly enabled using
        # the `enable_cpu_load_monitor` method.
        self._cpu_load_monitor = None

        # External clone/exec tool, because Python can't into clone
        self.bin_cloner_path = bin_cloner_path

    def kill(self):
        """All clean up associated with this microVM should go here."""
        # pylint: disable=subprocess-run-check
        if self.logging_thread is not None:
            self.logging_thread.stop()

        if self._jailer.daemonize:
            if self.jailer_clone_pid:
                utils.run_cmd(
                    'kill -9 {}'.format(self.jailer_clone_pid),
                    ignore_return_code=True)
        else:
            utils.run_cmd(
                'screen -XS {} kill'.format(self._session_name))

        if self._memory_monitor and self._memory_monitor.is_alive():
            self._memory_monitor.signal_stop()
            self._memory_monitor.join(timeout=1)
            self._memory_monitor.check_samples()

        if self._cpu_load_monitor:
            self._cpu_load_monitor.signal_stop()
            self._cpu_load_monitor.join()
            self._cpu_load_monitor.check_samples()

    @property
    def api_session(self):
        """Return the api session associated with this microVM."""
        return self._api_session

    @property
    def api_socket(self):
        """Return the socket used by this api session."""
        # TODO: this methods is only used as a workaround for getting
        # firecracker PID. We should not be forced to make this public.
        return self._api_socket

    @property
    def path(self):
        """Return the path on disk used that represents this microVM."""
        return self._path

    @property
    def id(self):
        """Return the unique identifier of this microVM."""
        return self._microvm_id

    @property
    def jailer(self):
        """Return the jailer context associated with this microVM."""
        return self._jailer

    @jailer.setter
    def jailer(self, jailer):
        """Setter for associating a different jailer to the default one."""
        self._jailer = jailer

    @property
    def kernel_file(self):
        """Return the name of the kernel file used by this microVM to boot."""
        return self._kernel_file

    @kernel_file.setter
    def kernel_file(self, path):
        """Set the path to the kernel file."""
        self._kernel_file = path

    @property
    def initrd_file(self):
        """Return the name of the initrd file used by this microVM to boot."""
        return self._initrd_file

    @initrd_file.setter
    def initrd_file(self, path):
        """Set the path to the initrd file."""
        self._initrd_file = path

    @property
    def log_data(self):
        """Return the log data."""
        return self._log_data

    @property
    def rootfs_file(self):
        """Return the path to the image this microVM can boot into."""
        return self._rootfs_file

    @rootfs_file.setter
    def rootfs_file(self, path):
        """Set the path to the image associated."""
        self._rootfs_file = path

    @property
    def fsfiles(self):
        """Path to filesystem used by this microvm to attach new drives."""
        return self._fsfiles_path

    @property
    def ssh_config(self):
        """Get the ssh configuration used to ssh into some microVMs."""
        return self._ssh_config

    @ssh_config.setter
    def ssh_config(self, key, value):
        """Set the dict values inside this configuration."""
        self._ssh_config.__setattr__(key, value)

    @property
    def memory_monitor(self):
        """Get the memory monitor."""
        return self._memory_monitor

    @memory_monitor.setter
    def memory_monitor(self, monitor):
        """Set the memory monitor."""
        self._memory_monitor = monitor

    def flush_metrics(self, metrics_fifo):
        """Flush the microvm metrics.

        Requires specifying the configured metrics file.
        """
        # Empty the metrics pipe.
        _ = metrics_fifo.sequential_reader(100)

        response = self.actions.put(action_type='FlushMetrics')
        assert self.api_session.is_status_no_content(response.status_code)

        lines = metrics_fifo.sequential_reader(100)
        assert len(lines) == 1

        return json.loads(lines[0])

    def get_all_metrics(self, metrics_fifo):
        """Return all metric data points written by FC.

        Requires specifying the configured metrics file.
        """
        # Empty the metrics pipe.
        response = self.actions.put(action_type='FlushMetrics')
        assert self.api_session.is_status_no_content(response.status_code)

        return metrics_fifo.sequential_reader(1000)

    def append_to_log_data(self, data):
        """Append a message to the log data."""
        self._log_data += data

    def enable_cpu_load_monitor(self, threshold):
        """Enable the cpu load monitor."""
        process_pid = self.jailer_clone_pid
        # We want to monitor the emulation thread, which is currently
        # the first one created.
        # A possible improvement is to find it by name.
        thread_pid = self.jailer_clone_pid
        self._cpu_load_monitor = cpu_tools.CpuLoadMonitor(
            process_pid,
            thread_pid,
            threshold
        )
        self._cpu_load_monitor.start()

    def create_jailed_resource(self, path, create_jail=False):
        """Create a hard link to some resource inside this microvm."""
        return self.jailer.jailed_path(path, create=True,
                                       create_jail=create_jail)

    def get_jailed_resource(self, path):
        """Get the relative jailed path to a resource."""
        return self.jailer.jailed_path(path, create=False)

    def chroot(self):
        """Get the chroot of this microVM."""
        return self.jailer.chroot_path()

    def setup(self):
        """Create a microvm associated folder on the host.

        The root path of some microvm is `self._path`.
        Also creates the where essential resources (i.e. kernel and root
        filesystem) will reside.

         # Microvm Folder Layout

             There is a fixed tree layout for a microvm related folder:

             ``` file_tree
             <microvm_uuid>/
                 kernel/
                     <kernel_file_n>
                     ....
                 fsfiles/
                     <fsfile_n>
                     <initrd_file_n>
                     <ssh_key_n>
                     <other fsfiles>
                     ...
                  ...
             ```
        """
        os.makedirs(self._path, exist_ok=True)
        os.makedirs(self._kernel_path, exist_ok=True)
        os.makedirs(self._fsfiles_path, exist_ok=True)

    def init_snapshot_api(self):
        """Initialize snapshot helpers."""
        self.snapshot_create = SnapshotCreate(
            self._api_socket,
            self._api_session
        )
        self.snapshot_load = SnapshotLoad(
            self._api_socket,
            self._api_session
        )

    def spawn(self, create_logger=True, log_file='log_fifo', log_level='Info'):
        """Start a microVM as a daemon or in a screen session."""
        # pylint: disable=subprocess-run-check
        self._jailer.setup()
        self._api_socket = self._jailer.api_socket_path()
        self._api_session = Session()

        self.actions = Actions(self._api_socket, self._api_session)
        self.boot = BootSource(self._api_socket, self._api_session)
        self.drive = Drive(self._api_socket, self._api_session)
        self.logger = Logger(self._api_socket, self._api_session)
        self.machine_cfg = MachineConfigure(
            self._api_socket,
            self._api_session
        )
        self.metrics = Metrics(self._api_socket, self._api_session)
        self.mmds = MMDS(self._api_socket, self._api_session)
        self.network = Network(self._api_socket, self._api_session)
        self.vm = Vm(self._api_socket, self._api_session)
        self.vsock = Vsock(self._api_socket, self._api_session)

        self.init_snapshot_api()

        if create_logger:
            log_fifo_path = os.path.join(self.path, log_file)
            log_fifo = log_tools.Fifo(log_fifo_path)
            self.create_jailed_resource(log_fifo.path, create_jail=True)
            # The default value for `level`, when configuring the
            # logger via cmd line, is `Warning`. We set the level
            # to `Info` to also have the boot time printed in fifo.
            self.jailer.extra_args.update({'log-path': log_file,
                                           'level': log_level})
            self.start_console_logger(log_fifo)

        jailer_param_list = self._jailer.construct_param_list()

        # When the daemonize flag is on, we want to clone-exec into the
        # jailer rather than executing it via spawning a shell. Going
        # forward, we'll probably switch to this method for running
        # Firecracker in general, because it represents the way it's meant
        # to be run by customers (together with CLONE_NEWPID flag).
        #
        # We have to use an external tool for CLONE_NEWPID, because
        # 1) Python doesn't provide a os.clone() interface, and
        # 2) Python's ctypes libc interface appears to be broken, causing
        # our clone / exec to deadlock at some point.
        if self._jailer.daemonize:
            if self.bin_cloner_path:
                cmd = [self.bin_cloner_path] + \
                      [self._jailer_binary_path] + \
                    jailer_param_list
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
                # This code path is not used at the moment, but I just feel
                # it's nice to have a fallback mechanism in place, in case
                # we decide to offload PID namespacing to the jailer.
                _pid = os.fork()
                if _pid == 0:
                    os.execv(
                        self._jailer_binary_path,
                        [self._jailer_binary_path] + jailer_param_list
                    )
                self.jailer_clone_pid = _pid
        else:
            # Delete old screen log if any.
            try:
                os.unlink(self.SCREEN_LOGFILE)
            except OSError:
                pass
            # Log screen output to SCREEN_LOGFILE
            # This file will collect any output from 'screen'ed Firecracker.
            start_cmd = 'screen -L -Logfile {logfile} '\
                        '-dmS {session} {binary} {params}'.format(
                            logfile=self.SCREEN_LOGFILE,
                            session=self._session_name,
                            binary=self._jailer_binary_path,
                            params=' '.join(jailer_param_list))

            utils.run_cmd(start_cmd)

            # Build a regex object to match (number).session_name
            regex_object = re.compile(
                r'([0-9]+)\.{}'.format(self._session_name))

            # Run 'screen -ls' in a retry_call loop, 30 times with a one
            # second delay between calls.
            # If the output of 'screen -ls' matches the regex object, it will
            # return the PID. Otherwise a RuntimeError will be raised.
            screen_pid = retry_call(
                utils.search_output_from_cmd,
                fkwargs={
                    "cmd": 'screen -ls',
                    "find_regex": regex_object
                },
                exceptions=RuntimeError,
                tries=30,
                delay=1).group(1)

            self.jailer_clone_pid = open('/proc/{0}/task/{0}/children'
                                         .format(screen_pid)
                                         ).read().strip()

            # Configure screen to flush stdout to file.
            flush_cmd = 'screen -S {session} -X colon "logfile flush 0^M"'
            utils.run_cmd(flush_cmd.format(session=self._session_name))

        # Wait for the jailer to create resources needed, and Firecracker to
        # create its API socket.
        # We expect the jailer to start within 80 ms. However, we wait for
        # 1 sec since we are rechecking the existence of the socket 5 times
        # and leave 0.2 delay between them.
        if 'no-api' not in self._jailer.extra_args:
            self._wait_create()
        if create_logger:
            self.check_log_message("Running Firecracker")

    @retry(delay=0.2, tries=5)
    def _wait_create(self):
        """Wait until the API socket and chroot folder are available."""
        os.stat(self._jailer.api_socket_path())

    @retry(delay=0.1, tries=5)
    def check_log_message(self, message):
        """Wait until `message` appears in logging output."""
        assert message in self._log_data

    def serial_input(self, input_string):
        """Send a string to the Firecracker serial console via screen."""
        input_cmd = 'screen -S {session} -p 0 -X stuff "{input_string}^M"'
        utils.run_cmd(input_cmd.format(session=self._session_name,
                                       input_string=input_string))

    def basic_config(
        self,
        vcpu_count: int = 2,
        ht_enabled: bool = False,
        mem_size_mib: int = 256,
        add_root_device: bool = True,
        boot_args: str = None,
        use_initrd: bool = False,
        track_dirty_pages: bool = False
    ):
        """Shortcut for quickly configuring a microVM.

        It handles:
        - CPU and memory.
        - Kernel image (will load the one in the microVM allocated path).
        - Root File System (will use the one in the microVM allocated path).
        - Does not start the microvm.

        The function checks the response status code and asserts that
        the response is within the interval [200, 300).
        """
        response = self.machine_cfg.put(
            vcpu_count=vcpu_count,
            ht_enabled=ht_enabled,
            mem_size_mib=mem_size_mib,
            track_dirty_pages=track_dirty_pages
        )
        assert self._api_session.is_status_no_content(response.status_code)

        if self.memory_monitor:
            self.memory_monitor.guest_mem_mib = mem_size_mib
            self.memory_monitor.pid = self.jailer_clone_pid
            self.memory_monitor.start()

        boot_source_args = {
            'kernel_image_path': self.create_jailed_resource(self.kernel_file),
            'boot_args': boot_args
        }

        if use_initrd and self.initrd_file != '':
            boot_source_args.update(
                initrd_path=self.create_jailed_resource(self.initrd_file))

        response = self.boot.put(**boot_source_args)
        assert self._api_session.is_status_no_content(response.status_code)

        if add_root_device and self.rootfs_file != '':
            # Add the root file system with rw permissions.
            response = self.drive.put(
                drive_id='rootfs',
                path_on_host=self.create_jailed_resource(self.rootfs_file),
                is_root_device=True,
                is_read_only=False
            )
            assert self._api_session.is_status_no_content(response.status_code)

    def add_drive(
            self,
            drive_id,
            file_path,
            root_device=False,
            is_read_only=False,
            partuuid=None,
    ):
        """Add a block device."""
        response = self.drive.put(
            drive_id=drive_id,
            path_on_host=self.create_jailed_resource(file_path),
            is_root_device=root_device,
            is_read_only=is_read_only,
            partuuid=partuuid
        )
        assert self.api_session.is_status_no_content(response.status_code)

    def patch_drive(self, drive_id, file):
        """Modify/patch an existing block device."""
        response = self.drive.patch(
            drive_id=drive_id,
            path_on_host=self.create_jailed_resource(file.path),
        )
        assert self.api_session.is_status_no_content(response.status_code)

    def ssh_network_config(
            self,
            network_config,
            iface_id,
            allow_mmds_requests=False,
            tx_rate_limiter=None,
            rx_rate_limiter=None,
            tapname=None
    ):
        """Create a host tap device and a guest network interface.

        'network_config' is used to generate 2 IPs: one for the tap device
        and one for the microvm. Adds the hostname of the microvm to the
        ssh_config dictionary.
        :param network_config: UniqueIPv4Generator instance
        :param iface_id: the interface id for the API request
        :param allow_mmds_requests: specifies whether requests sent from
        the guest on this interface towards the MMDS address are
        intercepted and processed by the device model.
        :param tx_rate_limiter: limit the tx rate
        :param rx_rate_limiter: limit the rx rate
        :return: an instance of the tap which needs to be kept around until
        cleanup is desired, the configured guest and host ips, respectively.
        """
        # Create tap before configuring interface.
        tapname = tapname or (self.id[:8] + 'tap' + iface_id)
        (host_ip, guest_ip) = network_config.get_next_available_ips(2)
        tap = self.create_tap_and_ssh_config(host_ip,
                                             guest_ip,
                                             network_config.get_netmask_len(),
                                             tapname)
        guest_mac = net_tools.mac_from_ip(guest_ip)

        response = self.network.put(
            iface_id=iface_id,
            host_dev_name=tapname,
            guest_mac=guest_mac,
            allow_mmds_requests=allow_mmds_requests,
            tx_rate_limiter=tx_rate_limiter,
            rx_rate_limiter=rx_rate_limiter
        )
        assert self._api_session.is_status_no_content(response.status_code)

        return tap, host_ip, guest_ip

    def create_tap_and_ssh_config(
            self,
            host_ip,
            guest_ip,
            netmask_len,
            tapname=None
    ):
        """Create tap device and configure ssh."""
        assert tapname is not None
        tap = net_tools.Tap(
            tapname,
            self._jailer.netns,
            ip="{}/{}".format(
                host_ip,
                netmask_len
            )
        )
        self.config_ssh(guest_ip)
        return tap

    def config_ssh(self, guest_ip):
        """Configure ssh."""
        self.ssh_config['hostname'] = guest_ip

    def start(self):
        """Start the microvm.

        This function has asserts to validate that the microvm boot success.
        """
        response = self.actions.put(action_type='InstanceStart')
        assert self._api_session.is_status_no_content(response.status_code)

    def pause_to_snapshot(self,
                          mem_file_path=None,
                          snapshot_path=None,
                          diff=False,
                          version=None):
        """Pauses the microVM, and creates snapshot.

        This function validates that the microVM pauses successfully and
        creates a snapshot.
        """
        assert mem_file_path is not None, "Please specify mem_file_path."
        assert snapshot_path is not None, "Please specify snapshot_path."

        response = self.vm.patch(state='Paused')
        assert self.api_session.is_status_no_content(response.status_code)

        response = self.snapshot_create.put(mem_file_path=mem_file_path,
                                            snapshot_path=snapshot_path,
                                            diff=diff,
                                            version=version)
        assert self.api_session.is_status_no_content(response.status_code)

    def resume_from_snapshot(self, mem_file_path, snapshot_path):
        """Resume snapshotted microVM in a new Firecracker process.

        Starts a new Firecracker process, loads a microVM from snapshot
        and resumes it.

        This function validates that resuming works.
        """
        assert mem_file_path is not None, "Please specify mem_file_path."
        assert snapshot_path is not None, "Please specify snapshot_path."

        self.jailer.cleanup(reuse_jail=True)
        self.spawn(create_logger=False)

        response = self.snapshot_load.put(mem_file_path=mem_file_path,
                                          snapshot_path=snapshot_path)

        assert self.api_session.is_status_no_content(response.status_code)

        response = self.vm.patch(state='Resumed')
        assert self.api_session.is_status_no_content(response.status_code)

    def start_console_logger(self, log_fifo):
        """
        Start a thread that monitors the microVM console.

        The console output will be redirected to the log file.
        """
        def monitor_fd(microvm, path):
            try:
                fd = open(path, "r")
                while True:
                    if microvm.logging_thread.stopped():
                        return
                    data = fd.readline()
                    if data:
                        microvm.append_to_log_data(data)
            except IOError as error:
                LOG.error("[%s] IOError while monitoring fd:"
                          " %s", microvm.id, error)
                microvm.append_to_log_data(str(error))
                return

        self.logging_thread = utils.StoppableThread(
            target=monitor_fd,
            args=(self, log_fifo.path),
            daemon=True)
        self.logging_thread.start()


class Serial:
    """Class for serial console communication with a Microvm."""

    RX_TIMEOUT_S = 5

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

        screen_log_fd = os.open(Microvm.SCREEN_LOGFILE, os.O_RDONLY)
        self._poller = select.poll()
        self._poller.register(screen_log_fd,
                              select.POLLIN | select.POLLHUP)

    def tx(self, input_string, end='\n'):
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
                output_char = str(os.read(fd, 1),
                                  encoding='utf-8',
                                  errors='ignore')
                return output_char

        return ''

    def rx(self, token="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Read a string delimited by an end token (defaults to "\n")."""
        rx_str = ''
        start = time.time()
        while True:
            rx_str += self.rx_char()
            if rx_str.endswith(token):
                break
            if (time.time() - start) >= self.RX_TIMEOUT_S:
                assert False

        return rx_str
