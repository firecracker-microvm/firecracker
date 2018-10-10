"""Classes for working with microVMs.

This module defines `MicrovmSlot` and `Microvm`, which can be used together
to create, test drive, and destroy microvms (based on microvm images).

# TODO

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
"""

import ctypes
import ctypes.util
import os
import shutil
from subprocess import run, PIPE
from threading import Thread
import time
import urllib

import requests_unixsocket

import host_tools.network as net_tools
import host_tools.cargo_build as build_tools

from framework.defs import FC_BINARY_NAME, \
    JAILER_BINARY_NAME, API_USOCKET_URL_PREFIX
from framework.jailer import JailerContext
from framework.resources import Actions, BootSource, Drive, Logger, MMDS, \
    MachineConfigure, Network


class MicrovmSlot:
    """A microvm slot with everything that's needed for a Firecracker microvm.

    Contains:
    - A location for kernel, rootfs, and other fsfiles.
    - The ability to create and keep track of additional fsfiles.
    - The ability to create and keep track of tap devices.

    `setup()` and `teardown()` handle the lifecycle of these resources.

    # Microvm Slot Layout

    There is a fixed tree layout for a microvm slot:

    ``` file_tree
    <microvm_slot_name>/
        kernel/
            <kernel_file_n>
            ....
        fsfiles/
            <fsfile_n>
            <ssh_key_n>
            ...
    ```

    Creating a microvm slot does *not* make a microvm image available, or any
    other microvm resources. A microvm image must be added to the microvm slot.
    MicrovmSlot methods can be used to create tap devices and fsfiles.
    """

    DEFAULT_MICROVM_ROOT_PATH = '/tmp/firecracker/'
    """Default path on the system where microvm slots will be created."""

    MICROVM_SLOT_DIR_PREFIX = 'microvm_slot_'

    MICROVM_SLOT_KERNEL_RELPATH = 'kernel/'
    """Relative path to the root of a slot for kernel files."""

    MICROVM_SLOT_FSFILES_RELPATH = 'fsfiles/'
    """Relative path to the root of a slot for filesystem files."""

    created_microvm_root_path = False
    """Keep track if the root path ws created here, so we can clean up."""

    def __init__(
        self,
        jailer_context: JailerContext,
        slot_id: str = "firecracker_slot",
        microvm_root_path=DEFAULT_MICROVM_ROOT_PATH
    ):
        """Set up microVM slot paths and data structures."""
        self.jailer_context = jailer_context
        self.slot_id = slot_id
        self.microvm_root_path = microvm_root_path
        self.path = os.path.join(
            microvm_root_path,
            self.MICROVM_SLOT_DIR_PREFIX + self.slot_id
        )
        self.kernel_path = os.path.join(
            self.path,
            self.MICROVM_SLOT_KERNEL_RELPATH
        )
        self.fsfiles_path = os.path.join(
            self.path,
            self.MICROVM_SLOT_FSFILES_RELPATH
        )

        self.kernel_file = ''
        """Assigned once an microvm image populates this slot."""
        self.rootfs_file = ''
        """ Assigned once an microvm image populates this slot. """

    def say(self, message: str):
        """Return a message from your microVM slot."""
        return "Microvm slot " + self.slot_id + ": " + message

    def setup(self):
        """Create a microvm slot on the host.

        The slot path is `<self.microvm_root_path>/<self.path>/`. Also creates
        `self.microvm_root_path` if it does not exist.
        """
        if not os.path.exists(self.microvm_root_path):
            os.makedirs(self.microvm_root_path)
            self.created_microvm_root_path = True

        os.makedirs(self.path, exist_ok=True)
        os.makedirs(self.kernel_path, exist_ok=True)
        os.makedirs(self.fsfiles_path, exist_ok=True)

    def netns(self):
        """Return the jailer context netns."""
        return self.jailer_context.netns

    def netns_file_path(self):
        """Return the jailer context netns file path."""
        return self.jailer_context.netns_file_path()

    def netns_cmd_prefix(self):
        """Return the jailer context netns file prefix."""
        if self.netns():
            return 'ip netns exec {} '.format(self.netns())
        return ''

    def cleanup(self):
        """Delete a local microvm slot.

        Also delete `[self.microvm_root_path]` if it has no other
        subdirectories, and it was created by this class.
        """
        shutil.rmtree(self.path)
        if (
            not os.listdir(self.microvm_root_path) and
            self.created_microvm_root_path
        ):
            os.rmdir(self.microvm_root_path)


class Microvm:
    """A Firecracker microvm. It goes into a microvm slot.

    Besides keeping track of microvm resources and exposing microvm API
    methods, `spawn()` and `kill()` can be used to start/end the microvm
    process.

    # TODO
    - Use the Firecracker Open API spec to populate Microvm API resource URLs.
    - Get the API paths from the Firecracker API definition.
    """

    MAX_MEMORY = 5 * 1024
    MEMORY_COP_TIMEOUT = 1

    def __init__(
        self,
        microvm_slot: MicrovmSlot,
        microvm_id: str = "firecracker_microvm",
        fc_binary_rel_path=os.path.join(
            build_tools.CARGO_RELEASE_REL_PATH,
            build_tools.RELEASE_BINARIES_REL_PATH
        ),
        monitor_memory=True
    ):
        """Set up microVM attributes, paths, and data structures."""
        self.slot = microvm_slot

        self.microvm_id = microvm_id
        self.fc_binary_path = os.path.join(
            microvm_slot.microvm_root_path,
            fc_binary_rel_path
        )
        self.jailer_clone_pid = None

        self.session_name = FC_BINARY_NAME + '-' + self.microvm_id

        self.api_usocket_full_name = \
            self.slot.jailer_context.api_socket_path()
        url_encoded_path = urllib.parse.quote_plus(self.api_usocket_full_name)
        self.api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        # The ssh config dictionary is populated with information about how
        # to connect to microvm that has ssh capability. The path of the
        # private key is populated by microvms with ssh capabilities and the
        # hostname is set from the MAC address used to configure the VM.
        self.ssh_config = {
            'username': 'root',
            'netns_file_path': self.slot.jailer_context.netns_file_path()
        }

        self.memory_cop_thread = None
        self.mem_size_mib = None
        self.monitor_memory = monitor_memory

        def start_api_session():
            """Return a unixsocket-capable http session object."""
            def is_good_response(response: int):
                """Return `True` for all HTTP 2xx response codes."""
                return 200 <= response < 300

            session = requests_unixsocket.Session()
            session.is_good_response = is_good_response
            return session

        self.api_session = start_api_session()
        self.actions = Actions(self.api_usocket_full_name, self.api_session)
        self.boot = BootSource(self.api_usocket_full_name, self.api_session)
        self.drive = Drive(self.api_usocket_full_name, self.api_session)
        self.logger = Logger(self.api_usocket_full_name, self.api_session)
        self.mmds = MMDS(self.api_usocket_full_name, self.api_session)
        self.network = Network(self.api_usocket_full_name, self.api_session)
        self.machine_cfg = MachineConfigure(
            self.api_usocket_full_name,
            self.api_session
        )

    def say(self, message: str):
        """Return a message from your microVM slot."""
        return "Microvm " + self.microvm_id + ": " + message

    def kernel_api_path(self, create=False):
        """Return the kernel image path."""
        # TODO: this function and the next are both returning the path to the
        #       kernel/filesystem image, and setting up the links inside the
        #       jail (when necessary). This is more or less a hack until we
        #       move to making API requests via helper methods. We assume they
        #       are only going to be invoked while building the bodies for
        #       requests which are about to be sent to the API server.
        return self.slot.jailer_context.jailed_path(
            self.slot.kernel_file,
            create=create
        )

    def rootfs_api_path(self):
        """Return the root filesystem path."""
        return self.slot.jailer_context.jailed_path(
            self.slot.rootfs_file,
            create=True
        )

    def chroot_path(self):
        """Return the jail chroot path."""
        return self.slot.jailer_context.chroot_path()

    def is_daemonized(self):
        """Return the daemonization status of the jail."""
        return self.slot.jailer_context.daemonize

    def spawn(self):
        """Start a microVM in a screen session, using an existing microVM slot.

        Returns the API socket URL.
        """
        self.ensure_firecracker_binary()

        fc_binary = os.path.join(self.fc_binary_path, FC_BINARY_NAME)

        context = self.slot.jailer_context

        jailer_binary = os.path.join(
            self.fc_binary_path,
            JAILER_BINARY_NAME
        )

        jailer_params_list = [
            '--id',
            str(context.microvm_slot_id),
            '--exec-file',
            fc_binary,
            '--uid',
            str(context.uid),
            '--gid',
            str(context.gid),
            '--node',
            str(context.numa_node)
        ]

        if context.netns:
            jailer_params_list.append('--netns')
            jailer_params_list.append(context.netns_file_path())

        # When the daemonize flag is on, we want to clone-exec into the
        # jailer rather than executing it via spawning a shell. Going
        # forward, we'll probably switch to this method for running
        # Firecracker in general, because it represents the way it's meant
        # to be run by customers (together with CLONE_NEWPID flag).

        if context.daemonize:
            jailer_params_list = ['jailer'] + jailer_params_list
            jailer_params_list.append('--daemonize')

            def exec_func():
                os.execv(jailer_binary, jailer_params_list)
                return -1

            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            stack_size = 4096
            stack = ctypes.c_char_p(b' ' * stack_size)
            stack_top = ctypes.c_void_p(
                ctypes.cast(
                    stack,
                    ctypes.c_void_p
                ).value
                + stack_size
            )
            exec_func_c = ctypes.CFUNCTYPE(ctypes.c_int)(exec_func)

            # Don't know how to refer to defines with ctypes & libc.
            clone_newpid = 0x20000000

            self.jailer_clone_pid = libc.clone(
                exec_func_c,
                stack_top,
                clone_newpid
            )
            return self.api_url

        start_cmd = 'screen -dmS {session} {binary} {params}'
        start_cmd = start_cmd.format(
            session=self.session_name,
            binary=jailer_binary,
            params=' '.join(jailer_params_list)
        )

        run(start_cmd, shell=True, check=True)
        return self.api_url

    def wait_create(self):
        """Wait until the API socket and chroot folder are available.

        The chroot folder is only applicable when running jailed.
        """
        # TODO: if appears that, since this function is used somewhere in
        # fixture setup logic or something like that, it's not subject to
        # timeout restrictions. If this loops forever because, for example the
        # jailer is not started properly and does not get to create the
        # resources we are looking for, the whole test suite will hang.
        # Is this observation correct? If so, fix at some point.

        while True:
            time.sleep(0.001)
            # TODO: Switch to getting notified somehow when things get created?
            if not os.path.exists(self.api_usocket_full_name):
                continue
            if self.chroot_path() and not os.path.exists(self.chroot_path()):
                continue
            break

    def basic_config(
        self,
        vcpu_count: int = 2,
        ht_enabled: bool = False,
        mem_size_mib: int = 256,
        add_root_device: bool = True
    ):
        """Shortcut for quickly configuring a spawned microvm.

        It handles:
        - CPU and memory.
        - Kernel image (will load the one in the microvm slot).
        - Root File System (will use the one in the microvm slot).
        - Does not start the microvm.

        The function checks the response status code and asserts that
        the response is within the interval [200, 300).
        """
        response = self.machine_cfg.put(
            vcpu_count=vcpu_count,
            ht_enabled=ht_enabled,
            mem_size_mib=mem_size_mib
        )
        assert self.api_session.is_good_response(response.status_code)

        if self.monitor_memory:
            self.mem_size_mib = mem_size_mib
            # The memory monitor thread uses the configured size of the guest's
            # memory region to exclude it from the total vss.
            self.memory_cop_thread = Thread(target=self._memory_cop)
            self.memory_cop_thread.start()

        # Add a kernel to start booting from.
        response = self.boot.put(
            kernel_image_path=self.kernel_api_path(create=True)
        )
        assert self.api_session.is_good_response(response.status_code)

        if add_root_device:
            # Add the root file system with rw permissions.
            response = self.drive.put(
                drive_id='rootfs',
                path_on_host=self.rootfs_api_path(),
                is_root_device=True,
                is_read_only=False
            )
            assert self.api_session.is_good_response(response.status_code)

    def ssh_network_config(self, network_config, iface_id,
                           allow_mmds_requests=False):
        """Create a host tap device and a guest network interface.

        'network_config' is used to generate 2 IPs: one for the tap device
        and one for the microvm. Adds the hostname of the microvm to the
        ssh_config dictionary.
        :param network_config: UniqueIPv4Generator instance
        :param iface_id: the interface id for the API request
        :param allow_mmds_requests: specifies whether requests sent from
        the guest on this interface towards the MMDS address are
        intercepted and processed by the device model.
        :return: an instance of the tap which needs to be kept around until
        cleanup is desired.
        """
        # Create tap before configuring interface.
        tapname = self.slot.slot_id[:8] + 'tap' + iface_id

        (host_ip, guest_ip) = network_config.get_next_available_ips(2)
        tap = net_tools.Tap(
            tapname,
            self.slot.netns(),
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
            allow_mmds_requests=allow_mmds_requests
        )
        assert self.api_session.is_good_response(response.status_code)

        self.ssh_config['hostname'] = guest_ip
        return tap

    def start(self):
        """Start the microvm.

        This function has asserts to validate that the microvm boot success.
        """
        # Start the microvm.
        response = self.actions.put(action_type='InstanceStart')
        assert self.api_session.is_good_response(response.status_code)

    def kill(self):
        """Kill a Firecracker microVM process.

        Does not issue a stop command to the guest.
        """
        if self.is_daemonized():
            run('kill -9 {}'.format(self.jailer_clone_pid), shell=True)
        else:
            run(
                'screen -XS {} kill'.format(self.session_name),
                shell=True
            )

    def ensure_firecracker_binary(self):
        """Build a Firecracker and Jailer binaries if they don't exist."""
        fc_binary_path = os.path.join(self.fc_binary_path, FC_BINARY_NAME)
        jailer_binary_path = os.path.join(
            self.fc_binary_path,
            JAILER_BINARY_NAME
        )
        if (
            not os.path.isfile(fc_binary_path)
            or
            not os.path.isfile(jailer_binary_path)
        ):
            build_path = os.path.join(
                self.slot.microvm_root_path,
                build_tools.CARGO_RELEASE_REL_PATH
            )
            build_tools.cargo_build(
                build_path,
                flags='--release',
                extra_args='>/dev/null 2>&1'
            )

    def _memory_cop(self):
        """Monitor memory consumption.

        `pmap` is used to compute Firecracker's memory overhead. If it exceeds
        the maximum value, the process exits immediately, failing any running
        test.

        Firecracker's pid is required for this functionality, therefore this
        thread will only run when jailed.
        """
        if not self.jailer_clone_pid or not self.mem_size_mib:
            # TODO Grep the log for the guest's memory space offset in order to
            # identify its memory regions, instead of relying on the configured
            # memory size as this may cause false positives. This will be fixed
            # when the logging flushing issues are. See #468.
            return

        pmap_cmd = 'pmap -xq {}'.format(self.jailer_clone_pid)

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
                total_size = 0
                rss = 0
                try:
                    total_size = int(tokens[1])
                    rss = int(tokens[2])
                except ValueError:
                    # This line doesn't contain memory related information.
                    continue
                if total_size == self.mem_size_mib * 1024:
                    # This is the guest's memory region.
                    # TODO Check for the address of the guest's memory instead.
                    continue
                mem_total += rss

            if mem_total > self.MAX_MEMORY:
                print('ERROR! Memory usage exceeded limit: {}'
                      .format(mem_total))
                exit(-1)

            if not mem_total:
                # Until we have a reliable way to a) kill Firecracker, b) know
                # Firecracker is dead, this will have to do.
                return

            time.sleep(self.MEMORY_COP_TIMEOUT)
