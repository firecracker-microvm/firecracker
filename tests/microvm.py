"""
This module defines `MicrovmSlot` and `Microvm`, which can be used together
to create, test drive, and destroy microvms (based on microvm images).

# Notes

- Programming here is not defensive, since tests systems turn false negatives
  into a quality-improving positive feedback loop.

# TODO

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
"""

import os
import shutil
from subprocess import run
import time
import urllib

import requests_unixsocket

from host_tools.cargo_build import cargo_build, CARGO_RELEASE_REL_PATH,\
    RELEASE_BINARIES_REL_PATH
from host_tools.network import mac_from_ip


class JailerContext:
    """ Describes the jailer configuration. This is a parameter of each
    MicrovmSlot, and the end goal here is to run Firecracker jailed for every
    relevant test.
    """

    def default_with_id(id: str):
        return JailerContext(id=id, numa_node=0, uid=1234, gid=1234,
                             chroot_base='/srv/jailer', netns=None,
                             daemonize=False)

    def __init__(self, id: str, numa_node: int, uid: int, gid: int,
                 chroot_base: str, netns: str, daemonize: bool):
        self.id = id
        self.numa_node = numa_node
        self.uid = uid
        self.gid = gid
        self.chroot_base = chroot_base
        self.netns = netns
        self.daemonize = daemonize


class FilesystemFile:
    """ Facility for creating and working with filesystem files. """

    KNOWN_FILEFS_FORMATS = {'ext4'}
    LOOP_MOUNT_PATH_SUFFIX = 'loop_mount_path/'

    def __init__(self, path: str, size: int=256, format: str='ext4'):
        """
        Creates a new file system in a file. Raises if the file system format
        is not supported, if the file already exists, or if it ends in '/'.
        """

        if format not in self.KNOWN_FILEFS_FORMATS:
            raise ValueError(
                'Format not in: + ' + str(self.KNOWN_FILEFS_FORMATS)
            )
        if path.endswith('/'):
            raise ValueError("Path ends in '/': " + path)
        if os.path.isfile(path):
            raise ValueError("File already exists: " + path)

        run(
            'dd status=none if=/dev/zero'
            '    of=' + path +
            '    bs=1M count=' + str(size),
            shell=True,
            check=True
        )
        run('mkfs.ext4 -qF ' + path, shell=True, check=True)
        self.path = path

    def copy_to(self, src_path, rel_dst_path):
        """ Copy to a relative path inside this filesystem file. """
        self._loop_mount()
        full_dst_path = os.path.join(self.loop_mount_path, rel_dst_path)

        try:
            os.makedirs(os.path.dirname(full_dst_path), exist_ok=True)
            shutil.copy(src_path, full_dst_path)
        finally:
            self._unmount()

    def copy_from(self, rel_src_path, dst_path):
        """ Copies from a relative path inside this filesystem file. """
        self._loop_mount()
        full_src_path = os.path.join(self.loop_mount_path, rel_src_path)

        try:
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            shutil.copy(full_src_path, dst_path)
        finally:
            self._unmount()

    def resize(self, new_size):
        """ Resizes the filesystem file. """
        run(
            'truncate --size ' + str(new_size) + 'M ' + self.path,
            shell=True,
            check=True
        )
        run('resize2fs ' + self.path, shell=True, check=True)

    def size(self):
        """ Returns the size of the filesystem file. """
        statinfo = os.stat(self.path)
        return statinfo.st_size

    def create_file(self, rel_path, content=None):
        """ Creates a file inside this filesystem file. """
        self._loop_mount()
        
    def _loop_mount(self):
        """
        Loop-mounts this file system file and saves the mount path.
        Always unmount with _unmount() as soon as possible.
        """
        loop_mount_path = self.path + '.' + self.LOOP_MOUNT_PATH_SUFFIX
        os.makedirs(loop_mount_path, exist_ok=True)
        run(
            'mount -o loop {fs_file} {mount_path}'.format(
                fs_file=self.path,
                mount_path=loop_mount_path
            ),
            shell=True,
            check=True
        )
        os.sync()
        self.loop_mount_path = loop_mount_path

    def _unmount(self):
        """ Unmounts this loop-mounted file system """
        os.sync()
        run(
            'umount {mount_path}'.format(mount_path=self.loop_mount_path),
            shell=True,
            check=True
        )
        self.loop_mount_path = None


class MicrovmSlot:
    """
    A microvm slot with everything that's needed for a Firecracker microvm:
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
    """ Default path on the system where microvm slots will be created. """

    MICROVM_SLOT_DIR_PREFIX = 'microvm_slot_'

    MICROVM_SLOT_KERNEL_RELPATH = 'kernel/'
    """ Relative path to the root of a slot for kernel files. """

    MICROVM_SLOT_FSFILES_RELPATH = 'fsfiles/'
    """ Relative path to the root of a slot for filesystem files. """

    created_microvm_root_path = False
    """
    Class variable to keep track if the root path was created by an object of
    this class, since we need to clean up if that is the case.
    """

    def __init__(
        self, jailer_context: JailerContext,
        id: str="firecracker_slot",
        microvm_root_path=DEFAULT_MICROVM_ROOT_PATH
    ):
        self.jailer_context = jailer_context
        self.id = id
        self.microvm_root_path = microvm_root_path
        self.path = os.path.join(
            microvm_root_path,
            self.MICROVM_SLOT_DIR_PREFIX + self.id
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
        """ Assigned once an microvm image populates this slot. """
        self.rootfs_file = ''
        """ Assigned once an microvm image populates this slot. """
        self.ssh_config = {'username': 'root'}
        """The ssh config dictionary is populated with information about how
        to connect to microvm that has ssh capability. The path of the private
        key is populated by microvms with ssh capabilities and the hostname
        is set from the MAC address used to configure the VM."""

        self.fsfiles = {}
        """ A set of file systems for this microvm slot. """
        self.taps = set()
        """ A set of tap devices for this microvm slot. """
        self.fifos = set()
        """ A set of named pipes for this microvm slot. """

    def say(self, message: str):
        return "Microvm slot " + self.id + ": " + message

    def setup(self):
        """
        Creates a local microvm slot under
        `[self.microvm_root_path]/[self.path]/`. Also creates
        `self.microvm_root_path` if it does not exist.
        """

        if not os.path.exists(self.microvm_root_path):
            os.makedirs(self.microvm_root_path)
            self.created_microvm_root_path = True

        os.makedirs(self.path)
        os.makedirs(self.kernel_path)
        os.makedirs(self.fsfiles_path)

    def make_fsfile(self, name: str=None, size: int=256):
        """ Creates an new file system in a file. `size` is in MiB. """

        if name is None:
            name = 'fsfile' + str(len(self.fsfiles) + 1)

        path = os.path.join(self.fsfiles_path, name + '.ext4')
        self.fsfiles[name] = FilesystemFile(path, size=size, format='ext4')
        return path

    def resize_fsfile(self, name, size):
        """
        Resizes the backing file of a guest's file system. `size` is in MiB.
        """

        fsfile = self.fsfiles[name]
        if not fsfile:
            raise ValueError(self.say("Invalid block device ID: " + name))
        fsfile.resize(size)

    def sizeof_fsfile(self, name):
        """ Returns the size of the backing file of a guest's filesystem. """
        fsfile = self.fsfiles[name]
        if not fsfile:
            raise ValueError(self.say("Invalid block device ID: " + name))
        return fsfile.size()

    def make_tap(self, name: str=None, ip: str=None):
        """ Creates a new tap device, and brings it up. """

        if name is None:
            name = self.id[:8] + '_tap' + str(len(self.taps) + 1)

        if os.path.isfile('/dev/tap/' + name):
            raise ValueError(self.say("Tap already exists: " + name))

        run('ip tuntap add mode tap name ' + name, shell=True, check=True)
        if ip:
            run("ifconfig {} {} up".format(name, ip), shell=True, check=True)

        self.taps.add(name)
        return name

    def make_fifo(self, name: str=None):
        """ Creates a new named pipe. """

        if name is None:
            name = 'fifo'  + str(len(self.fifos) + 1)

        path = os.path.join(self.path, name)
        if os.path.exists(path):
            raise ValueError(self.say("Named pipe already exists: " + path))

        run('mkfifo ' + path, shell=True, check=True)
        self.fifos.add(path)
        return path

    def teardown(self):
        """
        Deletes a local microvm slot. Also deletes `[self.microvm_root_path]`
        if it has no other subdirectories, and it was created by this class.
        """

        shutil.rmtree(self.path)
        if (
            not os.listdir(self.microvm_root_path) and
            self.created_microvm_root_path
        ):
            os.rmdir(self.microvm_root_path)

        for tap in self.taps:
            run('ip link set ' + tap + ' down', shell=True, check=True)
            run('ip link delete ' + tap, shell=True, check=True)
            run('ip tuntap del mode tap name ' + tap, shell=True, check=True)


class Microvm:
    """
    A Firecracker microvm. It goes into a microvm slot.

    Besides keeping track of microvm resources and exposing microvm API
    methods, `spawn()` and `kill()` can be used to start/end the microvm
    process.

    # TODO

    - Use the Firecracker Open API spec to populate Microvm API resource URLs.
    """

    FC_BINARY_NAME = 'firecracker'

    fc_start_cmd = 'screen -dmS {session} {fc_binary} --api-sock {fc_usock}'
    fc_stop_cmd = 'screen -XS {session} kill'

    api_usocket_name = 'api.socket'
    api_usocket_url_prefix = 'http+unix://'

    microvm_cfg_resource = 'machine-config'
    net_cfg_resource = 'network-interfaces'
    blk_cfg_resource = 'drives'
    boot_cfg_resource = 'boot-source'
    actions_resource = 'actions'
    logger_resource = 'logger'
    mmds_resource = 'mmds'
    # TODO: Get the API paths from the Firecracker API definition.

    def __init__(
        self,
        microvm_slot: MicrovmSlot,
        id: str="firecracker_microvm",
        fc_binary_rel_path=os.path.join(
            CARGO_RELEASE_REL_PATH,
            RELEASE_BINARIES_REL_PATH
        ),
        fc_binary_name=FC_BINARY_NAME
    ):
        self.slot = microvm_slot
        self.id = id
        self.fc_binary_path = os.path.join(
            microvm_slot.microvm_root_path,
            fc_binary_rel_path
        )
        self.fc_binary_name = fc_binary_name

        self.session_name = self.fc_binary_name + '-' + self.id

        api_usocket_full_name = os.path.join(
            self.slot.path,
            self.api_usocket_name
        )
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        self.api_url = self.api_usocket_url_prefix + url_encoded_path + '/'

        self.api_session = self._start_api_session()

    def _start_api_session(self):
        """ Returns a unixsocket-capable http session object. """

        def _is_good_response(response: int):
            """ Returns `True` for all HTTP 2xx response codes. """
            if 200 <= response < 300:
                return True
            else:
                return False

        session = requests_unixsocket.Session()
        session.is_good_response = _is_good_response

        return session

    def say(self, message: str):
        return "Microvm " + self.id + ": " + message

    def spawn(self):
        """
        Start a microVM in a screen session, using an existing microVM slot.
        Returns the API socket URL.
        """

        self.microvm_cfg_url = self.api_url + self.microvm_cfg_resource
        self.net_cfg_url = self.api_url + self.net_cfg_resource
        self.blk_cfg_url = self.api_url + self.blk_cfg_resource
        self.boot_cfg_url = self.api_url + self.boot_cfg_resource
        self.actions_url = self.api_url + self.actions_resource
        self.logger_url = self.api_url + self.logger_resource
        self.mmds_url = self.api_url + self.mmds_resource

        self.ensure_firecracker_binary()

        start_fc_session_cmd = self.fc_start_cmd.format(
            session=self.session_name,
            fc_binary=os.path.join(self.fc_binary_path, self.fc_binary_name),
            fc_usock=os.path.join(self.slot.path, self.api_usocket_name)
        )
        run(start_fc_session_cmd, shell=True, check=True)

        return self.api_url

    def basic_config(
        self,
        vcpu_count: int=2,
        ht_enable: bool=False,
        mem_size_mib: int=256,
        net_iface_count: int=1,
        add_root_device: bool=True,
        log_enable: bool=False,
        log_fifo: str='firecracker.pipe',
        metrics_fifo: str='metrics.pipe'
    ):
        """
        Shortcut for quickly configuring a spawned microvm. Only handles:
        - CPU and memory.
        - Network interfaces (supports at most 10).
        - Kernel image (will load the one in the microvm slot).
        - Root File System (will use the one in the microvm slot).
        - Logger and metrics named pipes.
        - Does not start the microvm.
        The function checks the response status code and asserts that
        the response is between 200 and 300.
        """

        if net_iface_count > 10:
            raise ValueError("Supports at most 10 network interfaces.")

        if log_enable:
            self.basic_logger_config(log_fifo=log_fifo, metrics_fifo=metrics_fifo)

        response = self.api_session.put(
            self.microvm_cfg_url,
            json={
                'vcpu_count': vcpu_count,
                'ht_enabled': ht_enable,
                'mem_size_mib': mem_size_mib
            }
        )
        assert(self.api_session.is_good_response(response.status_code))

        for net_iface_index in range(1, net_iface_count + 1):
            response = self.api_session.put(
                self.net_cfg_url + '/' + str(net_iface_index),
                json={
                    'iface_id': str(net_iface_index),
                    'host_dev_name': self.slot.make_tap(),
                    'guest_mac': '06:00:00:00:00:0' + str(net_iface_index),
                    'state': 'Attached'
                }
            )
            """ Maps the passed host network device into the microVM. """
            assert(self.api_session.is_good_response(response.status_code))

        response = self.api_session.put(
            self.boot_cfg_url,
            json={
                'boot_source_id': '1',
                'source_type': 'LocalImage',
                'local_image': {'kernel_image_path': self.slot.kernel_file}
            }
        )
        """ Adds a kernel to start booting from. """
        assert(self.api_session.is_good_response(response.status_code))

        if add_root_device:
            response = self.api_session.put(
                self.blk_cfg_url + '/rootfs',
                json={
                    'drive_id': 'rootfs',
                    'path_on_host': self.slot.rootfs_file,
                    'is_root_device': True,
                    'is_read_only': False
                }
            )
            """ Adds the root file system with rw permissions. """
            assert(self.api_session.is_good_response(response.status_code))

    def put_default_scratch_device(self):
        """
        Sets up a scratch rw block device for the microVM from a newly created
        FilesystemFile.
        """

        response = self.api_session.put(
            self.blk_cfg_url + '/scratch',
            json={
                'drive_id': 'scratch',
                'path_on_host': self.slot.make_fsfile(name='scratch'),
                'is_root_device': False,
                'is_read_only': False
            }
        )
        assert(self.api_session.is_good_response(response.status_code))

    def basic_network_config(self, network_config):
        """
        Creates a tap device on the host and a network interface on the guest.
        Uses network_config to generate 2 IPs: one for the tap device
        and one for the microvm. Adds the hostname of the microvm to the
        ssh_config dictionary.
        :param network_config: UniqueIPv4Generator instance
        """
        # For the cpu tests we need two IPs, one for the host and one for
        # the guest
        (host_ip, guest_ip) = network_config.get_next_available_ips(2)

        # Configure the tap device and add the network interface
        tap_name = self.slot.make_tap(
            ip="{}/{}".format(host_ip, network_config.get_netmask_len()))

        # We have to make sure that the microvm will be in the same
        # subnet as the tap device. The IP of the microvm is computed from the
        # mac address. To set the IP of the microvm to 192.168.241.2, we
        # need to set the mac to XX:XX:C0:A8:F1:02, where the first 2 bytes
        # are ignored and the next 4 bytes from the IP.
        iface_id = "1"
        response = self.api_session.put(
            "{}/{}".format(self.net_cfg_url, iface_id),
            json={
                "iface_id": iface_id,
                "host_dev_name": tap_name,
                "guest_mac": mac_from_ip(guest_ip),
                "state": "Attached"
            }
        )
        assert (self.api_session.is_good_response(response.status_code))

        # we can now update the ssh_config dictionary with the IP of the VM.
        self.slot.ssh_config['hostname'] = guest_ip

    def basic_logger_config(
            self,
            log_fifo: str='firecracker.pipe',
            metrics_fifo: str='metrics.pipe'
    ):
        """ Configures logging. """
        response = self.api_session.put(
            self.logger_url,
            json={
                'log_fifo': self.slot.make_fifo(log_fifo),
                'metrics_fifo': self.slot.make_fifo(metrics_fifo),
                'level': 'Info',
                'show_level': True,
                'show_log_origin': True
            }
        )
        assert(self.api_session.is_good_response(response.status_code))

    def start(self):
        """
        Start the microvm. This function has asserts in order to validate
        that the microvm boot was successful.
        """
        # Start the microvm.
        response = self.api_session.put(
            self.actions_url + '/1',
            json={'action_id': '1', 'action_type': 'InstanceStart'}
        )
        assert(self.api_session.is_good_response(response.status_code))

        # Wait for the microvm to start.
        time.sleep(1)
        # Check that the Instance Start was successful
        response = self.api_session.get(self.actions_url + '/1')
        assert (self.api_session.is_good_response(response.status_code))

    def kill(self):
        """
        Kills a Firecracker microVM process. Does not issue a stop command to
        the guest.
        """
        run(
            self.fc_stop_cmd.format(session=self.session_name),
            shell=True,
            check=True
        )

    def ensure_firecracker_binary(self):
        """ If no firecracker binary exists in the binaries path, build it. """
        binary_path=os.path.join(self.fc_binary_path, self.fc_binary_name)
        if not os.path.isfile(binary_path):
            build_path = os.path.join(
                self.slot.microvm_root_path,
                CARGO_RELEASE_REL_PATH
            )
            cargo_build(
                build_path,
                flags="--release",
                extra_args=">/dev/null 2>&1"
            )
