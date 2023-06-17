# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=redefined-outer-name

"""
Each microVM needs to have a unique IP on the host network, or there will be
conflicts.

Helper classes to hand out IPs.
"""

import math
import os
from ipaddress import ip_network

import pytest


class SubnetGenerator:
    """Simple subnet allocator"""

    def __init__(self, network_str, subnet_netmask_len=24):
        self.network = ip_network(network_str)
        netmask_len_diff = subnet_netmask_len - self.network.prefixlen
        self._subnets = self.network.subnets(netmask_len_diff)
        self._returned_subnets = []

    def borrow_subnet(self):
        """Borrow a subnet from the pool"""
        if len(self._returned_subnets) > 0:
            return self._returned_subnets.pop(0)
        return next(self._subnets)

    def return_subnet(self, subnet):
        """Return a subnet to the pool"""
        self._returned_subnets.append(subnet)


class IPv4Generator:
    """Simple IPv4 allocator"""

    def __init__(self, network):
        self.network = network
        self._hosts = enumerate(self.network)

    def next_ip(self):
        """Get the next ip"""
        return next(self._hosts)

    def get_next_available_ips_aligned(self, count, netmask_len=30):
        """
        Allocate `count` contiguous IPs within the same `netmask_len` network.
        """
        align = 2 ** (32 - netmask_len)
        if count > align:
            raise ValueError("Cannot give IPs in the same subnet")
        ips = []
        remaining = count
        while remaining > 0:
            i, ip = self.next_ip()
            next_aligned_subnet = math.ceil(i / align) * align
            # if we don't have enough IPs left at this alignment, get to the
            # next network start
            if i + remaining >= next_aligned_subnet:
                for _ in range(next_aligned_subnet - i):
                    self.next_ip()
                continue
            # skip the network address
            if i % align == 0:
                continue
            ips.append(ip)
            remaining -= 1

        return [str(ip) for ip in ips]

    get_next_available_ips = get_next_available_ips_aligned


@pytest.fixture(scope="session")
def subnet_generator(worker_id):
    """
    Yield a SubnetGenerator per pytest worker

    We use the 16-bit block 192.168.0.0/16 as it's (empirically) the least
    likely to conflict with a cloud provider private IPs.
    https://en.wikipedia.org/wiki/Private_network
    """
    # Example worker_id = gw4
    worker_num = 0 if worker_id == "master" else int(worker_id[2:])

    # We use the worker id to carve separate networks, as large as possible
    worker_count = int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", 1))
    bits = math.ceil(math.log2(worker_count))
    netmask = 16  # we use 192.168.0.0/16
    netmask += bits
    o3 = 2 ** (8 - bits) * worker_num

    # Most tests just need a /30, but some tests may want more IPs, so we give
    # each single test a whole /24. This is OK since those /24s are returned at
    # the end of the test.
    return SubnetGenerator(f"192.168.{o3}.0/{netmask}", 24)


@pytest.fixture
def network_config(subnet_generator):
    """Yield an IPv4Generator per test"""
    subnet = subnet_generator.borrow_subnet()
    yield IPv4Generator(subnet)
    subnet_generator.return_subnet(subnet)


if __name__ == "__main__":
    from ipaddress import IPv4Network

    ipgen = IPv4Generator(IPv4Network("192.168.0.0/16"))
    ipgen.get_next_available_ips(2, netmask_len=30)
    ipgen.get_next_available_ips(2, netmask_len=30)
