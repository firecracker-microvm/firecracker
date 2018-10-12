"""Utilities for test host microVM network setup."""

import os
import socket
import struct
import threading

from subprocess import run, PIPE

from paramiko import AutoAddPolicy, SSHClient, ssh_exception
from nsenter import Namespace
from retry.api import retry_call


class SSHConnection:
    """SSHConnection encapsulates functionality for microVM SSH interaction.

    This class should be instantiated as part of the ssh fixture with the
    the hostname obtained from the MAC address, the username for logging into
    the image and the path of the ssh key.

    The ssh config dictionary contains the following fields:
    * hostname
    * username
    * ssh_key_path

    This translates into an SSH connection as follows:
    ssh -i ssh_key_path username@hostname
    """

    def __init__(self, ssh_config):
        """Instantiate a SSH client and connect to a microVM."""
        self.netns_file_path = ssh_config['netns_file_path']
        self.ssh_client = SSHClient()  # pylint: disable=no-value-for-parameter
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        assert os.path.exists(ssh_config['ssh_key_path'])

        # Retry to connect to the host as long as the delay between calls
        # is less than 30 seconds. Sleep 1, 2, 4, 8, ... seconds between
        # attempts. These parameters might need additional tweaking when we
        # add tests with 1000 Firecracker microvm.

        # TODO: If a microvm runs in a particular network namespace, we have to
        # temporarily switch to that namespace when doing something that routes
        # packets over the network, otherwise the destination will not be
        # reachable. Use a better setup/solution at some point!

        if self.netns_file_path:
            with Namespace(self.netns_file_path, 'net'):
                self.initial_connect(ssh_config)
        else:
            self.initial_connect(ssh_config)

    def initial_connect(self, ssh_config):
        """Create an initial SSH client connection (retry until it works)."""
        retry_call(
            self.ssh_client.connect,
            fargs=[ssh_config['hostname']],
            fkwargs={
                'look_for_keys': False,
                'username': ssh_config['username'],
                'key_filename': ssh_config['ssh_key_path']
            },
            exceptions=ssh_exception.NoValidConnectionsError,
            delay=1,
            backoff=2,
            max_delay=32
        )

    def execute_command(self, cmd_string):
        """Execute the command passed as a string in the ssh context."""
        if self.netns_file_path:
            with Namespace(self.netns_file_path, 'net'):
                return self.ssh_client.exec_command(cmd_string)
        return self.ssh_client.exec_command(cmd_string)

    def close(self):
        """Close the SSH connection."""
        if self.netns_file_path:
            with Namespace(self.netns_file_path, 'net'):
                self.ssh_client.close()
        else:
            self.ssh_client.close()


class NoMoreIPsError(Exception):
    """No implementation required."""

    pass


class InvalidIPCount(Exception):
    """No implementation required."""

    pass


class SingletonReinitializationError(Exception):
    """No implementation required."""

    pass


class UniqueIPv4Generator:
    """Each microVM needs to have a unique IP on the host network."""

    __instance = None

    @staticmethod
    def get_instance():
        """Singleton implementation.

        This class should be instantiated once per test session. All the
        microvms will have to use the same netmask length for
        the generator to work.

        This class will only generate IP addresses from the ranges
        192.168.0.0 - 192.168.255.255 and 172.16.0.0 - 172.31.255.255 which
        are the private IPs sub-networks.

        For a network mask of 30 bits, the UniqueIPv4Generator can generate up
        to 16320 sub-networks, each with 2 valid IPs from the
        192.168.0.0 - 192.168.255.255 range and 244800 sub-networks from the
        172.16.0.0 - 172.31.255.255 range.
        """
        if not UniqueIPv4Generator.__instance:
            return UniqueIPv4Generator()

        return UniqueIPv4Generator.__instance

    @staticmethod
    def __ip_to_int(ip: str):
        return int.from_bytes(socket.inet_aton(ip), 'big')

    def __init__(self):
        """Don't call directly. Use get_instance instead."""
        if self.__instance:
            raise SingletonReinitializationError

        # For the IPv4 address range 192.168.0.0 - 192.168.255.255, the mask
        # length is 16 bits. This means that the netmask_len used to
        # initialize the class can't be smaller that 16. For now we stick to
        # the default mask length = 30.
        self.netmask_len = 30
        self.ip_range = [
            ('192.168.0.0', '192.168.255.255'),
            ('172.16.0.0', '172.31.255.255')
        ]
        # We start by consuming IPs from the first defined range.
        self.ip_range_index = 0
        # The ip_range_min_index is the first IP in the range that can be used.
        # For the first range, this corresponds to "192.168.0.0".
        self.ip_range_min_index = 0

        # The ip_range_max_index is the last IP in the range that can be used.
        # For the first range, this corresponds to "192.168.255.255".
        self.ip_range_max_index = 1
        self.next_valid_subnet_id = self.__ip_to_int(
            self.ip_range[self.ip_range_index][0]
        )

        # The subnet_len contains the number of valid IPs in a subnet and it is
        # used to increment the next_valid_subnet_id once a request for a
        # subnet is issued.
        self.subnet_max_ip_count = (1 << 32 - self.netmask_len)

        self.lock = threading.Lock()

        UniqueIPv4Generator.__instance = self

    def __ensure_next_subnet(self):
        """Raise an exception if there are no subnets available."""
        max_ip_as_int = self.__ip_to_int(
            self.ip_range[self.ip_range_index][self.ip_range_max_index]
        )

        # Check if there are any IPs left to use from the current range.
        if (
            self.next_valid_subnet_id + self.subnet_max_ip_count
            > max_ip_as_int
        ):
            # Check if there are any other IP ranges.
            if self.ip_range_index < len(self.ip_range) - 1:
                # Move to the next IP range.
                self.ip_range_index += 1
                self.next_valid_subnet_id = self.__ip_to_int(
                    self.ip_range[self.ip_range_index][self.ip_range_min_index]
                )
            else:
                # There are no other ranges defined, so no more unassigned IPs.
                raise NoMoreIPsError

    def get_netmask_len(self):
        """Return the network mask length."""
        return self.netmask_len

    def get_next_available_subnet_range(self):
        """Return a pair of IPS encompassing an unused subnet.

        :return: range of IPs (defined as a pair) from an unused subnet.
         The mask used is the one defined when instantiating the
         UniqueIPv4Generator class.
        """
        with self.lock:
            self.__ensure_next_subnet()
            next_available_subnet = (
                socket.inet_ntoa(
                    struct.pack('!L', self.next_valid_subnet_id)
                ),
                socket.inet_ntoa(
                    struct.pack(
                        '!L',
                        self.next_valid_subnet_id +
                        (self.subnet_max_ip_count - 1)
                    )
                )
            )

            self.next_valid_subnet_id += self.subnet_max_ip_count
            return next_available_subnet

    def get_next_available_ips(self, count):
        """Return a count of unique IPs.

        Raises InvalidIPCount when the requested IPs number is > than the
        length of the subnet mask -2. Two IPs from the subnet are reserved
        because the first address is the subnet identifier and the last IP is
        the broadcast IP.

        :param count: number of unique IPs to return
        :return: list of IPs as a list of strings
        """
        if count > self.subnet_max_ip_count - 2:
            raise InvalidIPCount

        with self.lock:
            self.__ensure_next_subnet()
            # The first IP in a subnet is the subnet identifier.
            next_available_ip = self.next_valid_subnet_id + 1
            ip_list = []
            for _ in range(count):
                ip_as_string = socket.inet_ntoa(
                    struct.pack('!L', next_available_ip)
                )
                ip_list.append(ip_as_string)
                next_available_ip += 1
            self.next_valid_subnet_id += self.subnet_max_ip_count
            return ip_list


def mac_from_ip(ip_address):
    """Create a MAC address based on the provided IP.

    Algorithm:
    - the first 2 bytes are fixed to 06:00
    - the next 4 bytes are the IP address

    Example of function call:
    mac_from_ip("192.168.241.2") -> 06:00:C0:A8:F1:02
    C0 = 192, A8 = 168, F1 = 241 and  02 = 2
    :param ip_address: IP address as string
    :return: MAC address from IP
    """
    mac_as_list = ['06', '00']
    mac_as_list.extend(
        list(
            map(
                lambda val: '{0:02x}'.format(int(val)),
                ip_address.split('.')
            )
        )
    )

    return "{}:{}:{}:{}:{}:{}".format(*mac_as_list)


class Tap:
    """Functionality for creating a tap and cleaning up after it."""

    def __init__(self, name, netns, ip=None):
        """Set up the name and network namespace for this tap interface.

        It also creates a new tap device, and brings it up. The tap will
        stay on the host as long as the object obtained by instantiating this
        class will be in scope. Once it goes out of scope, its destructor will
        get called and the tap interface will get removed.
        The function also moves the interface to the specified
        namespace.
        """
        run(
            'ip tuntap add mode tap name ' + name,
            shell=True,
            check=True
        )
        run(
            'ip link set {} netns {}'.format(name, netns),
            shell=True,
            check=True
        )
        if ip:
            run('ip netns exec {} ifconfig {} {} up'.format(
                netns,
                name,
                ip
            ), shell=True, check=True)
        self._name = name
        self._netns = netns

    @property
    def name(self):
        """Return the name of this tap interface."""
        return self._name

    @property
    def netns(self):
        """Return the network namespace of this tap."""
        return self._netns

    def __del__(self):
        """Destructor doing tap interface clean up."""
        _ = run(
            'ip netns exec {} ip link set {} down'.format(
                self.netns,
                self.name
            ),
            shell=True,
            stderr=PIPE
        )
        _ = run(
            'ip netns exec {} ip link delete {}'.format(self.netns, self.name),
            shell=True,
            stderr=PIPE
        )
        _ = run(
            'ip netns exec {} ip tuntap del mode tap name {}'.format(
                self.netns,
                self.name
            ),
            shell=True,
            stderr=PIPE
        )
