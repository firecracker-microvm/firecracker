# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests on devices config space."""

import platform
import random
import re
import string
import subprocess
from threading import Thread

import host_tools.network as net_tools  # pylint: disable=import-error

# pylint: disable=global-statement
PAYLOAD_DATA_SIZE = 20


def test_net_change_mac_address(test_microvm_with_api, change_net_config_space_bin):
    """
    Test changing the MAC address of the network device.
    """

    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config(boot_args="ipv6.disable=1")

    # Data exchange interface ('eth0' in guest).
    test_microvm.add_net_iface()
    # Control interface ('eth1' in guest).
    test_microvm.add_net_iface()
    test_microvm.start()

    # Create the control ssh connection.
    ssh_conn = test_microvm.ssh_iface(1)
    host_ip0 = test_microvm.iface["eth0"]["iface"].host_ip
    guest_ip0 = test_microvm.iface["eth0"]["iface"].guest_ip

    # Start a server(host) - client(guest) communication with the following
    # parameters.
    host_port = 4444
    iterations = 1
    _exchange_data(test_microvm.jailer, ssh_conn, host_ip0, host_port, iterations)

    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["net"]["tx_spoofed_mac_count"] == 0

    # Change the MAC address of the network data interface.
    # This change will be propagated only inside the net device kernel struct
    # and will be used for ethernet frames formation when data is exchanged
    # on the network interface.
    mac = "06:05:04:03:02:01"
    mac_hex = "0x060504030201"
    guest_if1_name = net_tools.get_guest_net_if_name(ssh_conn, guest_ip0)
    assert guest_if1_name is not None
    _change_guest_if_mac(ssh_conn, mac, guest_if1_name)

    _exchange_data(test_microvm.jailer, ssh_conn, host_ip0, host_port, iterations)

    # `tx_spoofed_mac_count` metric was incremented due to the MAC address
    # change.
    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["net"]["tx_spoofed_mac_count"] > 0

    net_addr_base = _get_net_mem_addr_base(ssh_conn, guest_if1_name)
    assert net_addr_base is not None

    # Write into '/dev/mem' the same mac address, byte by byte.
    # This changes the MAC address physically, in the network device registers.
    # After this step, the net device kernel struct MAC address will be the
    # same with the MAC address stored in the network device registers. The
    # `tx_spoofed_mac_count` metric shouldn't be incremented later on.
    rmt_path = "/tmp/change_net_config_space"
    test_microvm.ssh.scp_put(change_net_config_space_bin, rmt_path)
    cmd = f"chmod u+x {rmt_path} && {rmt_path} {net_addr_base} {mac_hex}"

    # This should be executed successfully.
    exit_code, stdout, stderr = ssh_conn.run(cmd)
    assert exit_code == 0, stderr
    assert stdout == mac

    # Discard any parasite data exchange which might've been
    # happened on the emulation thread while the config space
    # was changed on the vCPU thread.
    test_microvm.flush_metrics()

    _exchange_data(test_microvm.jailer, ssh_conn, host_ip0, host_port, iterations)
    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["net"]["tx_spoofed_mac_count"] == 0

    # Try again, just to be extra sure.
    _exchange_data(test_microvm.jailer, ssh_conn, host_ip0, host_port, iterations)
    fc_metrics = test_microvm.flush_metrics()
    assert fc_metrics["net"]["tx_spoofed_mac_count"] == 0


def _create_server(jailer, host_ip, port, iterations):
    # Wait for `iterations` TCP segments, on one connection.
    # This server has to run under the network namespace, initialized
    # by the integration test microvm jailer.
    # pylint: disable=global-statement
    script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.setsockopt(\n"
        "    socket.SOL_SOCKET, socket.SO_REUSEADDR,\n"
        "     s.getsockopt(socket.SOL_SOCKET,\n"
        "                 socket.SO_REUSEADDR) | 1\n"
        ")\n"
        "s.bind(('{}', {}))\n"
        "s.listen(1)\n"
        "conn, addr = s.accept()\n"
        "recv_iterations = {}\n"
        "while recv_iterations > 0:\n"
        "    data = conn.recv({})\n"
        "    recv_iterations -= 1\n"
        "conn.close()\n"
        "s.close()"
    )

    # The host uses Python3
    cmd = 'python3 -c "{}"'.format(
        script.format(host_ip, port, iterations, PAYLOAD_DATA_SIZE)
    )
    netns_cmd = jailer.netns_cmd_prefix() + cmd
    exit_code = subprocess.call(netns_cmd, shell=True)
    assert exit_code == 0


def _send_data_g2h(ssh_connection, host_ip, host_port, iterations, data, retries):
    script = (
        "import socket\n"
        "import time\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "retries={}\n"
        "while retries > 0:\n"
        "   try:\n"
        "       s.connect(('{}',{}))\n"
        "       retries = 0\n"
        "   except Exception as e:\n"
        "       retries -= 1\n"
        "       time.sleep(1)\n"
        "       if retries == 0:\n"
        "           exit(1)\n"
        "send_iterations={}\n"
        "while send_iterations > 0:\n"
        "   s.sendall(b'{}')\n"
        "   send_iterations -= 1\n"
        "s.close()"
    )

    # The guest has Python3
    cmd = 'python3 -c "{}"'.format(
        script.format(retries, host_ip, str(host_port), iterations, data)
    )

    # Wait server to initialize.
    exit_code, _, stderr = ssh_connection.run(cmd)
    # If this assert fails, a connection refused happened.
    assert exit_code == 0, stderr
    assert stderr == ""


def _start_host_server_thread(jailer, host_ip, host_port, iterations):
    thread = Thread(
        target=_create_server, args=(jailer, host_ip, host_port, iterations)
    )

    thread.start()
    return thread


def _exchange_data(jailer, ssh_control_connection, host_ip, host_port, iterations):
    server_thread = _start_host_server_thread(jailer, host_ip, host_port, iterations)

    # Generate random data.
    letters = string.ascii_lowercase
    data = "".join(random.choice(letters) for _ in range(PAYLOAD_DATA_SIZE))

    # We need to synchronize host server with guest client. Server thread has
    # to start listening for incoming connections before the client tries to
    # connect. To synchronize, we implement a polling mechanism, retrying to
    # establish a connection, on the client side, mechanism to retry guest
    # client socket connection, in case the server had not started yet.
    _send_data_g2h(
        ssh_control_connection, host_ip, host_port, iterations, data, retries=5
    )

    # Wait for host server to receive the data sent by the guest client.
    server_thread.join()


def _change_guest_if_mac(ssh_connection, guest_if_mac, guest_if_name):
    cmd = "ip link set dev {} address ".format(guest_if_name) + guest_if_mac
    # The connection will be down, because changing the mac will issue down/up
    # on the interface.
    ssh_connection.run(cmd)


def _get_net_mem_addr_base(ssh_connection, if_name):
    """Get the net device memory start address."""
    if platform.machine() == "x86_64":
        sys_virtio_mmio_cmdline = "/sys/devices/virtio-mmio-cmdline/"
        cmd = "ls {} | grep virtio-mmio. | sed 's/virtio-mmio.//'"
        exit_code, stdout, _ = ssh_connection.run(cmd.format(sys_virtio_mmio_cmdline))
        assert exit_code == 0
        virtio_devs_idx = stdout.split()

        cmd = "cat /proc/cmdline"
        exit_code, cmd_line, _ = ssh_connection.run(cmd)
        assert exit_code == 0
        pattern_dev = re.compile("(virtio_mmio.device=4K@0x[0-9a-f]+:[0-9]+)+")
        pattern_addr = re.compile("virtio_mmio.device=4K@(0x[0-9a-f]+):[0-9]+")
        devs_addr = []
        for dev in re.findall(pattern_dev, cmd_line):
            matched_addr = pattern_addr.search(dev)
            # The 1st group which matches this pattern
            # is the device start address. `0` group is
            # full match.
            addr = matched_addr.group(1)
            devs_addr.append(addr)

        cmd = "ls {}/virtio-mmio.{}/virtio{}/net"
        for idx in virtio_devs_idx:
            _, guest_if_name, _ = ssh_connection.run(
                cmd.format(sys_virtio_mmio_cmdline, idx, idx)
            )
            if guest_if_name.strip() == if_name:
                return devs_addr[int(idx)]
    elif platform.machine() == "aarch64":
        sys_virtio_mmio_cmdline = "/sys/devices/platform"
        cmd = "ls {} | grep .virtio_mmio".format(sys_virtio_mmio_cmdline)
        rc, stdout, _ = ssh_connection.run(cmd)
        assert rc == 0

        virtio_devs = stdout.split()
        devs_addr = list(map(lambda dev: dev.split(".")[0], virtio_devs))

        cmd = "ls {}/{}/virtio{}/net"
        # Device start addresses lack the hex prefix and are not interpreted
        # accordingly when parsed inside `change_config_space.c`.
        hex_prefix = "0x"
        for idx, dev in enumerate(virtio_devs):
            _, guest_if_name, _ = ssh_connection.run(
                cmd.format(sys_virtio_mmio_cmdline, dev, idx)
            )
            if guest_if_name.strip() == if_name:
                return hex_prefix + devs_addr[int(idx)]

    return None
