# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for network device emulation."""
import json
import os
import time
from subprocess import run
import pytest

import host_tools.logging as log_tools
import host_tools.network as net_tools  # pylint: disable=import-error

IPERF = "iperf3"
ITERATION_DURATION = 60
SOCKET_BUFFER_SIZE = 10

# BW in Mbits.
BANDWIDTHS = {
    "udp": [100, 5000, 10000],
    "tcp": [100, 5000, 10000, 0]
}

# From server to client and reversed.
MODES = ["h2g", "g2h"]
# Corresponding MODES for iperf options.
MODES_OPTIONS = {
    "h2g": "-R",
    "g2h": "",
}

# From server to client and reversed.
PROTOCOL = ["udp", "tcp"]
# Corresponding MODES for iperf options.
PROTOCOL_OPTIONS = {
    "tcp": "",
    "udp": "-u",
}


def spawn_host_iperf(netns_cmd_prefix):
    """Start iperf in server mode after killing any leftover iperf daemon."""
    # pylint: disable=subprocess-run-check
    iperf_cmd = 'pkill {}\n'.format(IPERF)

    # Don't check the result of this command because it can fail if no iperf
    # is running.
    run(iperf_cmd, shell=True)

    iperf_cmd = '{} {} -sD\n'.format(
        netns_cmd_prefix, IPERF)

    run(iperf_cmd, shell=True, check=True)

    # Wait for the iperf daemon to start.
    time.sleep(2)


def spawn_guest_iperf(microvm, iperf_cmd):
    """Run iperf in guest and return result json."""
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
    _, stdout, stderr = ssh_connection.execute_command(iperf_cmd)
    assert stderr.read().decode('utf-8') == ''

    out = stdout.read().decode('utf-8')
    return json.loads(out)


def parse_iperf_udp_result(result, mode, bw):
    """Parse iperf udp test output and return result json."""
    totals = result["end"]["sum"]
    total_bytes = int(totals["bytes"])
    total_packets = int(totals["packets"])
    lost_packets = int(totals["lost_packets"])
    duration = float(totals["seconds"])
    jitter = round(float(totals["jitter_ms"]), 2)
    tput = round((total_bytes*8) / (1024*1024*duration), 2)
    pps = round(total_packets / duration, 2)

    return {
        "test": "udp-{}-{}".format(mode, bw),
        "tput": tput,
        "lost": lost_packets,
        "pps": pps,
        "jitter": jitter,
    }


def parse_iperf_tcp_result(result, mode, bw):
    """Parse iperf tcp test output and return result json."""
    total_sent = result["end"]["sum_sent"]
    total_received = result["end"]["sum_received"]
    duration = float(total_received["seconds"])
    total_bytes_received = int(total_received["bytes"])
    retransmits = int(total_sent["retransmits"])

    # Measuring TPUT from rx-ing side.
    tput = round((total_bytes_received*8) / (1024*1024*duration), 2)

    return {
        "test": "tcp-{}-{}".format(mode, bw),
        "tput": tput,
        "retransmits": retransmits,
    }


@pytest.mark.timeout(3600)
@pytest.mark.env("benchmark")
def test_block_device_performance(test_microvm_with_ssh, network_config):
    """Execute net device emulation benchmarking scenarios."""
    microvm = test_microvm_with_ssh
    microvm.spawn()
    microvm.basic_config(mem_size_mib=1024)

    # Configure logging.
    log_fifo_path = os.path.join(microvm.path, 'log_fifo')
    metrics_fifo_path = os.path.join(microvm.path, 'metrics_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = microvm.logger.put(
        log_fifo=microvm.create_jailed_resource(log_fifo.path),
        metrics_fifo=microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    spawn_host_iperf(microvm.jailer.netns_cmd_prefix())

    _tap, host_ip, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()

    results = []

    for protocol in PROTOCOL_OPTIONS:
        for bw in BANDWIDTHS[protocol]:
            for mode in MODES:
                cmd = '{} -c {} -t{} -f MBytes -J -b {}M {} {} -w {}M'.format(
                    IPERF,
                    host_ip,
                    ITERATION_DURATION,
                    bw,
                    MODES_OPTIONS[mode],
                    PROTOCOL_OPTIONS[protocol],
                    SOCKET_BUFFER_SIZE
                )

                iperf_out = spawn_guest_iperf(microvm, cmd)
                result = None
                if protocol == "udp":
                    result = parse_iperf_udp_result(iperf_out, mode, bw)
                else:
                    result = parse_iperf_tcp_result(iperf_out, mode, bw)

                results.append(result)
                print(result)

    with open('test_net_performance.json', 'w') as outfile:
        json.dump(results, outfile, indent=4)

    # TODO: Compare values with a the baseline and fail test if required.
