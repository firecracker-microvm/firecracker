# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Classes for working with microVMs.

This module defines `Microvm`, which can be used to create, test drive, and
destroy microvms.

# TODO

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
"""

import os
from queue import Queue
import re
from subprocess import run, PIPE

from retry import retry

import host_tools.memory as mem_tools
import host_tools.network as net_tools

from framework.defs import MICROVM_KERNEL_RELPATH, MICROVM_FSFILES_RELPATH
from framework.http import Session
from framework.jailer import JailerContext
from framework.resources import Actions, BootSource, Drive, Logger, MMDS, \
    MachineConfigure, Network, Vsock


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
        microvm_id,
        build_feature='',
        monitor_memory=True,
        bin_cloner_path=None,
        config_file=None
    ):
        """Set up microVM attributes, paths, and data structures."""
        # Unique identifier for this machine.
        self._microvm_id = microvm_id

        self.build_feature = build_feature

        # Compose the paths to the resources specific to this microvm.
        self._path = os.path.join(resource_path, microvm_id)
        self._kernel_path = os.path.join(self._path, MICROVM_KERNEL_RELPATH)
        self._fsfiles_path = os.path.join(self._path, MICROVM_FSFILES_RELPATH)
        self._kernel_file = ''
        self._rootfs_file = ''

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
        self.mmds = None
        self.network = None
        self.machine_cfg = None
        self.vsock = None

        # Optional file that contains a json for configuring microvm from
        # command line parameter.
        self.config_file = config_file

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
            self._memory_events_queue = Queue()
        else:
            self._memory_events_queue = None

        # External clone/exec tool, because Python can't into clone
        self.bin_cloner_path = bin_cloner_path

    def kill(self):
        """All clean up associated with this microVM should go here."""
        if self._jailer.daemonize:
            if self.jailer_clone_pid:
                run('kill -9 {}'.format(self.jailer_clone_pid), shell=True)
        else:
            run(
                'screen -XS {} kill'.format(self._session_name),
                shell=True
            )

        if self._memory_events_queue and not self._memory_events_queue.empty():
            raise mem_tools.MemoryUsageExceededException(
                self._memory_events_queue.get())

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
    def memory_events_queue(self):
        """Get the memory usage events queue."""
        return self._memory_events_queue

    @memory_events_queue.setter
    def memory_events_queue(self, queue):
        """Set the memory usage events queue."""
        self._memory_events_queue = queue

    def create_jailed_resource(self, path, create_jail=False):
        """Create a hard link to some resource inside this microvm."""
        return self.jailer.jailed_path(path, create=True,
                                       create_jail=create_jail)

    def get_jailed_resource(self, path):
        """Get the jailed path to a resource."""
        return self.jailer.jailed_path(path, create=False)

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
                     <ssh_key_n>
                     <other fsfiles>
                     ...
                  ...
             ```
        """
        os.makedirs(self._path, exist_ok=True)
        os.makedirs(self._kernel_path, exist_ok=True)
        os.makedirs(self._fsfiles_path, exist_ok=True)

    def spawn(self):
        """Start a microVM as a daemon or in a screen session."""
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
        self.mmds = MMDS(self._api_socket, self._api_session)
        self.network = Network(self._api_socket, self._api_session)
        self.vsock = Vsock(self._api_socket, self._api_session)

        jailer_param_list = self._jailer.construct_param_list(self.config_file)

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
                _p = run(cmd, stdout=PIPE, stderr=PIPE, check=True)
                # Terrible hack to make the tests fail when starting the
                # jailer fails with a panic. This is needed because we can't
                # get the exit code of the jailer. In newpid_clone.c we are
                # not waiting for the process and we always return 0 if the
                # clone was successful (which in most cases will be) and we
                # don't do anything if the jailer was not started
                # successfully.
                if _p.stderr.decode().strip():
                    raise Exception(_p.stderr.decode())
                self.jailer_clone_pid = int(_p.stdout.decode().rstrip())
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
                os.unlink('/tmp/screen.log')
            except OSError:
                pass
            # Log screen output to /tmp/screen.log.
            # This file will collect any output from 'screen'ed Firecracker.
            start_cmd = 'screen -L -Logfile /tmp/screen.log '\
                        '-dmS {session} {binary} {params}'
            start_cmd = start_cmd.format(
                session=self._session_name,
                binary=self._jailer_binary_path,
                params=' '.join(jailer_param_list)
            )

            run(start_cmd, shell=True, check=True)

            out = run('screen -ls', shell=True, stdout=PIPE)\
                .stdout.decode('utf-8')
            screen_pid = re.search(r'([0-9]+)\.{}'.format(self._session_name),
                                   out).group(1)
            self.jailer_clone_pid = open('/proc/{0}/task/{0}/children'
                                         .format(screen_pid)
                                         ).read().strip()

            # Configure screen to flush stdout to file.
            flush_cmd = 'screen -S {session} -X colon "logfile flush 0^M"'
            run(flush_cmd.format(session=self._session_name),
                shell=True, check=True)

        # Wait for the jailer to create resources needed, and Firecracker to
        # create its API socket.
        # We expect the jailer to start within 80 ms. However, we wait for
        # 1 sec since we are rechecking the existence of the socket 5 times
        # and leave 0.2 delay between them.
        self._wait_create()

    @retry(delay=0.2, tries=5)
    def _wait_create(self):
        """Wait until the API socket and chroot folder are available."""
        os.stat(self._jailer.api_socket_path())

    def serial_input(self, input_string):
        """Send a string to the Firecracker serial console via screen."""
        input_cmd = 'screen -S {session} -p 0 -X stuff "{input_string}^M"'
        run(input_cmd.format(session=self._session_name,
                             input_string=input_string),
            shell=True, check=True)

    def basic_config(
        self,
        vcpu_count: int = 2,
        ht_enabled: bool = False,
        mem_size_mib: int = 256,
        add_root_device: bool = True,
        boot_args: str = None,
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
            mem_size_mib=mem_size_mib
        )
        assert self._api_session.is_status_no_content(response.status_code)

        if self.memory_events_queue:
            mem_tools.threaded_memory_monitor(
                mem_size_mib,
                self.jailer_clone_pid,
                self._memory_events_queue
            )

        # Add a kernel to start booting from.
        response = self.boot.put(
            kernel_image_path=self.create_jailed_resource(self.kernel_file),
            boot_args=boot_args
        )
        assert self._api_session.is_status_no_content(response.status_code)

        if add_root_device:
            # Add the root file system with rw permissions.
            response = self.drive.put(
                drive_id='rootfs',
                path_on_host=self.create_jailed_resource(self.rootfs_file),
                is_root_device=True,
                is_read_only=False
            )
            assert self._api_session.is_status_no_content(response.status_code)

    def ssh_network_config(
            self,
            network_config,
            iface_id,
            allow_mmds_requests=False,
            tx_rate_limiter=None,
            rx_rate_limiter=None
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
        tapname = self.id[:8] + 'tap' + iface_id
        (host_ip, guest_ip) = network_config.get_next_available_ips(2)
        tap = net_tools.Tap(
            tapname,
            self._jailer.netns,
            ip="{}/{}".format(
                host_ip,
                network_config.get_netmask_len()
            )
        )
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

        self.ssh_config['hostname'] = guest_ip
        return tap, host_ip, guest_ip

    def start(self):
        """Start the microvm.

        This function has asserts to validate that the microvm boot success.
        """
        response = self.actions.put(action_type='InstanceStart')
        assert self._api_session.is_status_no_content(response.status_code)
