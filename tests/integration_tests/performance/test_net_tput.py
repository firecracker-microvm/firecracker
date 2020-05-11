# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the network throughput overhead added by Firecracker."""

import json
import time
import statistics
import socket
from subprocess import run, PIPE
import pytest

from retry import retry

import host_tools.network as net_tools
from framework.statistics import Statistics
from framework.utils import get_cpus_in_numa

IPERF = 'iperf3'
OUTPUT_JSON = 'test_net_tput_{}_iperfs.json'
CSET_NAME = 'test_tput'

class IperfClient:
    # Flow direction and corresponding modes for iperf.
    MODES = {
        'h2g': '-R',
        'g2h': ''
    }
    # Iteration duration of a single run in seconds.
    ITERATION_DURATION = 1
    # Number of test runs.
    RUNS = 1
    PINNING_CPU = 1

    def __init__(self, protocol, host_ip, iperfs, microvm):
        self.host_ip = host_ip
        self.iperfs = iperfs
        self.microvm = microvm
        self.statistics = self.create_statistics()

    def build_params_map(self):
        """Build parameters map used for iperf."""
        specific_params = self.get_specific_params()
        params = {
            'host_ip': self.host_ip,
            'iperfs': self.iperfs,
            'protocol': specific_params['protocol'],
        }

        for _ in range(self.RUNS):
            for bw in specific_params['bandwidth']:
                for mode in self.MODES.items():
                    params['bw'] = bw
                    params['mode'] = mode[1]

                    yield params

    def build_iperf_cmd(self, params):
        """Build the iperf command applying given params."""

        cmd = '{} -c {} -t{} -f MBytes -J -b {}M {} {} -A {} -P {}'.format(
                IPERF,
                params['host_ip'],
                self.ITERATION_DURATION,
                params['bw'],
                params['mode'],
                params['protocol'],
                self.PINNING_CPU,
                params['iperfs'],
            )

        return cmd

    def spawn_iperf_guest(self, iperf_cmd):
        """Start iperf in client mode and return resulting JSON."""
        _, stdout, stderr = self.ssh_connection.execute_command(iperf_cmd)
        assert stderr.read() == ''

        out = stdout.read()
        return json.loads(out)

    def run_iperf_client(self, results):
        """Run an iperf client."""

        self.ssh_connection = net_tools.SSHConnection(self.microvm.ssh_config)

        for params in self.build_params_map():
            cmd = self.build_iperf_cmd(params)
            iperf_out = self.spawn_iperf_guest(cmd)
            result = self.parse_result(iperf_out, params)

            results.append(result)
        
        return statistics


class IperfUdpClient(IperfClient):
    def __init__(self, host_ip, iperfs, microvm):
        super().__init__('udp', host_ip, iperfs, microvm)

    def create_statistics(self):
        """Create a map which holds metric statistics registered for UDP."""
        return {
            'tput': Statistics(),
            'lost': Statistics(),
            'pps': Statistics(),
            'jitter': Statistics(),
        }

    def get_specific_params(self):
        """Get specific parameters for udp."""
        return {
            'protocol' : '-u',
            'bandwidth' : [100, 5000, 10000],
        }

    def parse_result(self, result, params):
        """Parse iperf UDP test output and return result JSON."""
        test = 'udp-{}-bw{}'.format(
                    'h2g' if params['mode'] == '-R' else 'g2h', 
                    params['bw'], 
                )

        totals = result['end']['sum']
        total_bytes = int(totals['bytes'])
        total_packets = int(totals['packets'])
        lost_packets = int(totals['lost_packets'])
        duration = float(totals['seconds'])
        jitter = round(float(totals['jitter_ms']), 2)
        tput = round((total_bytes*8) / (1024*1024*duration), 2)
        pps = round(total_packets / duration, 2)

        if test not in self.statistics:
            self.statistics[test] = self.create_statistics()

        self.statistics[test]['tput'].add(tput)
        self.statistics[test]['lost'].add(lost_packets)
        self.statistics[test]['pps'].add(pps)
        self.statistics[test]['jitter'].add(jitter)

        return {
            'test': test,
            'tput': tput,
            'lost': lost_packets,
            'pps': pps,
            'jitter': jitter,
        }


class IperfTcpClient(IperfClient):
    WINDOW_SIZE_MB = 10
    # Skip the first OMIT_TIME seconds when testing TCP
    # to avoid slow start.
    OMIT_TIME = 0
    PACKET_SIZE_KB = [128, 256, 1024, 1500]

    def __init__(self, host_ip, iperfs, microvm):
        super().__init__('tcp', host_ip, iperfs, microvm)

    def create_statistics(self):
        """Create a map which holds metric statistics registered for TCP."""
        return {
            'tput': Statistics(),
            'retransmits': Statistics(),
        }

    def get_specific_params(self):
        """Create specific parameters for tcp."""
        return {
            'protocol' : '',
            'bandwidth' : [5000, 10000, 20000, 0],
        }

    def build_params_map(self):
        """Build a parameters list specific to tcp."""
        for params in super().build_params_map():
            for window_size in range(2):
                for packet_size in self.PACKET_SIZE_KB:
                    params['window_size'] = window_size
                    params['packet_size'] = packet_size

                    yield params

    def build_iperf_cmd(self, params):
        """Build the iperf command applying given params."""
        cmd = super().build_iperf_cmd(params)

        cmd += ' -O {}'.format(self.OMIT_TIME)
        cmd += ' -l {}'.format(params['packet_size'])
        if params['window_size'] == 0:
            cmd += ' -w {}'.format(self.WINDOW_SIZE_MB)

        return cmd

    def parse_result(self, result, params):
        """Parse iperf TCP test output and return result JSON."""
        test = 'tcp-{}-bw{}-ps{}-ws{}'.format(
                    'h2g' if params['mode'] == '-R' else 'g2h', 
                    params['bw'], 
                    params['packet_size'], 
                    self.WINDOW_SIZE_MB if params['window_size'] == 0 else '-'
                )

        total_sent = result['end']['sum_sent']
        total_received = result['end']['sum_received']
        duration = float(total_received['seconds'])
        total_bytes_received = int(total_received['bytes'])
        retransmits = int(total_sent['retransmits'])

        # Measuring TPUT from rx-ing side.
        tput = round((total_bytes_received*8) / (1024*1024*duration), 2)

        if test not in self.statistics:
            self.statistics[test] = self.create_statistics()

        self.statistics[test]['tput'].add(tput)
        self.statistics[test]['retransmits'].add(retransmits)

        return {
            'test': test,
            'tput': tput,
            'retransmits': retransmits,
        }


def spawn_host_iperf(netns_cmd_prefix, host_ip):
    """Start iperf in server mode after killing any leftover iperf daemon."""
    iperf_cmd = 'pkill {}'.format(IPERF)

    # Don't check the result of this command because it can fail if no iperf
    # is running.
    run(iperf_cmd, shell=True, check=False)

    iperf_cmd = '{} {} -sD'.format(netns_cmd_prefix, IPERF)
    _p = run(iperf_cmd, shell=True, check=True, stdout=PIPE, stderr=PIPE)
    
    # Wait iperf server to start.
    time.sleep(1)


def run_network_tput_test(microvm, network_config, iperfs):
    """Execute network throughtput test."""

    vcpu_count = iperfs + 1
    microvm.spawn()
    microvm.basic_config(vcpu_count=vcpu_count, mem_size_mib=1024)

    _tap, host_ip, _ = microvm.ssh_network_config(network_config, '1')

    spawn_host_iperf(microvm.jailer.netns_cmd_prefix(), host_ip)

    microvm.start()
    numa_node = microvm._jailer.numa_node
    cpus_list = get_cpus_in_numa(numa_node, vcpu_count)

    microvm.shield_vm_vcpus(CSET_NAME, cpus_list, numa_node)

    results = []
    udp_client = IperfUdpClient(host_ip, iperfs, microvm)
    _ = udp_client.run_iperf_client(results)

    tcp_client = IperfTcpClient(host_ip, iperfs, microvm)
    _ = tcp_client.run_iperf_client(results)

    # TODO : compute statistics

    output_name = OUTPUT_JSON.format(iperfs)
    with open(output_name, 'w') as outfile:
        json.dump(results, outfile, indent=4)


@pytest.mark.timeout(3600)
#@pytest.mark.skip(reason="Work in progress")
def test_network_tput_1_iperf(test_microvm_with_ssh, network_config):
    """Test the throughtput with only one iperf."""
    run_network_tput_test(test_microvm_with_ssh, network_config, 1)


@pytest.mark.timeout(3600)
@pytest.mark.skip(reason="Work in progress")
def test_network_tput_2_iperf(test_microvm_with_ssh, network_config):
    """Test the throughtput with two iperfs running simultaneous."""
    run_network_tput_test(test_microvm_with_ssh, network_config, 2)
