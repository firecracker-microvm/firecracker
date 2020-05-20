# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network latency of a Firecracker guest."""

import re
import json
import platform
import pytest

import host_tools.network as net_tools

# Number of requests issued.
REQUESTS = 1000

# Interval time between requests.
INTERVAL = 0.2

PING = 'ping -c {} -i {} {}'
INT_REG = r'[0-9]+'
FLOAT_REG = r'[+-]?[0-9]+\.[0-9]+'
GOLDFILE = 'integration_tests/performance/goldfile.json'
TEST_NAME = 'network_latency'


def do_ping_on_guest(target, ssh_connection):
    """Ping the @target on the guest."""
    cmd = PING.format(REQUESTS, INTERVAL, target)
    _, stdout, stderr = ssh_connection.execute_command(cmd)

    assert stderr.read() == ''

    return stdout.read()


def get_statistics(output):
    """Get statistics out of a ping result."""
    # Get statistics on results.
    stat_names = ['min', 'avg', 'max', 'stdder']
    output = output.split('\n')

    stat_values = output[-2]
    stat_values = re.findall(FLOAT_REG, stat_values)

    statistics = {}
    for index, stat_value in enumerate(stat_values):
        statistics[stat_names[index]] = float(stat_value)

    # Get statistics on packet loss.
    packet_stats = output[-3]
    packet_stats = packet_stats.split(',')[2]
    packet_stats = re.findall(INT_REG, packet_stats)

    # Make sure we got only the packet loss percentage.
    assert len(packet_stats) == 1

    statistics['packet_loss%'] = float(packet_stats[0])

    # Compute percentiles.
    seqs = output[1:REQUESTS + 1]
    times = []
    for index, seq in enumerate(seqs):
        time = re.findall(FLOAT_REG + ' ms', seq)[0]
        time = re.findall(FLOAT_REG, time)[0]
        times.append(time)

    times.sort()
    statistics['p50'] = times[int(REQUESTS * 0.5)]
    statistics['p90'] = times[int(REQUESTS * 0.9)]
    statistics['p99'] = times[int(REQUESTS * 0.99)]

    return statistics


def check_results(result):
    """Compare the results with the ones in the goldfile."""
    assert float(result['packet_loss%']) == 0.0

    with open(GOLDFILE, 'r') as outfile:
        target = json.load(outfile)
        target = target[TEST_NAME][platform.machine()]

        target_result = float(target['target'])
        target_delta = float(target['delta'])

        assert abs(target_result - result['avg']) < target_delta


@pytest.mark.skip(reason="Work in progress")
def test_net_latency(test_microvm_with_ssh, network_config):
    """Send a ping from guest to host."""
    microvm = test_microvm_with_ssh
    microvm.spawn()
    microvm.basic_config(vcpu_count=2, mem_size_mib=1024)

    _tap, host_ip, _ = microvm.ssh_network_config(network_config, '1')
    microvm.start()

    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Ping g2h
    g2h = do_ping_on_guest(host_ip, ssh_connection)
    g2h_statistics = get_statistics(g2h)

    json_file = '{}.json'.format(TEST_NAME)
    with open(json_file, 'w') as outfile:
        json.dump(g2h_statistics, outfile, indent=4)

    check_results(g2h_statistics)
