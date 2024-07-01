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


def test_net_change_mac_address(uvm_plain_any, change_net_config_space_bin):
    """
    Test changing the MAC address of the network device.
    """

    test_microvm = uvm_plain_any
    test_microvm.help.enable_console()
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
    _, stdout, _ = ssh_conn.check_output(cmd)
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
    netns_cmd = jailer.netns.cmd_prefix() + " " + cmd
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
    _, _, stderr = ssh_connection.check_output(cmd)
    # If this assert fails, a connection refused happened.
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


def _find_iomem_range(ssh_connection, dev_name):
    # `/proc/iomem` includes information of the system's MMIO registered
    # slots. It looks like this:
    #
    # ```
    # ~ cat /proc/iomem
    # 00000000-00000fff : Reserved
    # 00001000-0007ffff : System RAM
    # 00080000-0009ffff : Reserved
    # 000f0000-000fffff : System ROM
    # 00100000-0fffffff : System RAM
    #   01000000-018031d0 : Kernel code
    #   018031d1-01c863bf : Kernel data
    #   01df8000-0209ffff : Kernel bss
    # d0000000-d0000fff : LNRO0005:00
    #   d0000000-d0000fff : LNRO0005:00
    # d0001000-d0001fff : LNRO0005:01
    #   d0001000-d0001fff : LNRO0005:01
    # ```
    #
    # So, to find the address range of a device we just `cat`
    # its contents and grep for the VirtIO device name, which
    # with ACPI is "LNRO0005:XY".
    cmd = f"cat /proc/iomem | grep -m 1 {dev_name}"
    rc, stdout, stderr = ssh_connection.run(cmd)
    assert rc == 0, stderr

    # Take range in the form 'start-end' from line. The line looks like this:
    # d00002000-d0002fff : LNRO0005:02
    mem_range = stdout.strip().split(" ")[0]

    # Parse range into (start, end) integers
    tokens = mem_range.split("-")
    return (int(tokens[0], 16), int(tokens[1], 16))


def _get_net_mem_addr_base_x86_acpi(ssh_connection, if_name):
    """Check for net device memory start address via ACPI info"""
    # On x86 we define VirtIO devices through ACPI AML bytecode. VirtIO devices
    # are identified as "LNRO0005" and appear under /sys/devices/platform
    sys_virtio_mmio_cmdline = "/sys/devices/platform/"
    cmd = "ls {}"
    _, stdout, _ = ssh_connection.check_output(cmd.format(sys_virtio_mmio_cmdline))
    virtio_devs = list(filter(lambda x: "LNRO0005" in x, stdout.strip().split()))

    # For virtio-net LNRO0005 devices, we should have a path like:
    # /sys/devices/platform/LNRO0005::XY/virtioXY/net which is a directory
    # that includes a subdirectory `ethZ` which represents the network device
    # that corresponds to the virtio-net device.
    cmd = "ls {}/{}/virtio{}/net"
    for idx, dev in enumerate(virtio_devs):
        _, guest_if_name, _ = ssh_connection.run(
            cmd.format(sys_virtio_mmio_cmdline, dev, idx)
        )
        if guest_if_name.strip() == if_name:
            return _find_iomem_range(ssh_connection, dev)[0]

    return None


def _get_net_mem_addr_base_x86_cmdline(ssh_connection, if_name):
    """Check for net device memory start address via command line arguments"""
    sys_virtio_mmio_cmdline = "/sys/devices/virtio-mmio-cmdline/"
    cmd = "ls {} | grep virtio-mmio. | sed 's/virtio-mmio.//'"
    exit_code, stdout, stderr = ssh_connection.run(cmd.format(sys_virtio_mmio_cmdline))
    assert exit_code == 0, stderr
    virtio_devs_idx = stdout.strip().split()

    cmd = "cat /proc/cmdline"
    _, cmd_line, _ = ssh_connection.check_output(cmd)
    pattern_dev = re.compile("(virtio_mmio.device=4K@0x[0-9a-f]+:[0-9]+)+")
    pattern_addr = re.compile("virtio_mmio.device=4K@(0x[0-9a-f]+):[0-9]+")
    devs_addr = []
    for dev in re.findall(pattern_dev, cmd_line):
        matched_addr = pattern_addr.search(dev)
        # The 1st group which matches this pattern
        # is the device start address. `0` group is
        # full match
        addr = matched_addr.group(1)
        devs_addr.append(addr)

    cmd = "ls {}/virtio-mmio.{}/virtio{}/net"
    for idx in virtio_devs_idx:
        _, guest_if_name, _ = ssh_connection.run(
            cmd.format(sys_virtio_mmio_cmdline, idx, idx)
        )
        if guest_if_name.strip() == if_name:
            return devs_addr[int(idx)]

    return None


def _get_net_mem_addr_base(ssh_connection, if_name):
    """Get the net device memory start address."""
    if platform.machine() == "x86_64":
        acpi_info = _get_net_mem_addr_base_x86_acpi(ssh_connection, if_name)
        if acpi_info is not None:
            return acpi_info

        return _get_net_mem_addr_base_x86_cmdline(ssh_connection, if_name)

    if platform.machine() == "aarch64":
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
