# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""File containing utility methods for iperf-based performance tests"""

import concurrent.futures
import json
import time

from framework import utils
from framework.utils import CmdBuilder, CpuMap, track_cpu_utilization


class IPerf3Test:
    """Class abstracting away the setup and execution of an iperf3-based performance test"""

    def __init__(
        self,
        microvm,
        base_port,
        runtime,
        omit,
        mode,
        num_clients,
        connect_to,
        *,
        iperf="iperf3",
        payload_length="DEFAULT",
    ):
        self._microvm = microvm
        self._base_port = base_port
        self._runtime = runtime
        self._omit = omit
        self._mode = mode  # entry into mode-map
        self._num_clients = num_clients
        self._connect_to = connect_to  # the "host" value to pass to "--client"
        self._payload_length = payload_length  # the value to pass to "--len"
        self._iperf = iperf
        self._guest_iperf = iperf

    def run_test(self, first_free_cpu):
        """Runs the performance test, using pinning the iperf3 servers to CPUs starting from `first_free_cpu`"""
        assert self._num_clients < CpuMap.len() - self._microvm.vcpus_count - 2

        for server_idx in range(self._num_clients):
            assigned_cpu = CpuMap(first_free_cpu)
            cmd = (
                self.host_command(server_idx)
                .with_arg("--affinity", assigned_cpu)
                .build()
            )
            utils.check_output(f"{self._microvm.netns.cmd_prefix()} {cmd}")
            first_free_cpu += 1

        # Wait for the iperf3 server to start
        time.sleep(2)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            cpu_load_future = executor.submit(
                track_cpu_utilization,
                self._microvm.firecracker_pid,
                # Ignore the final two data points as they are impacted by test teardown
                self._runtime - 2,
                self._omit,
            )

            clients = []
            for client_idx in range(self._num_clients):
                client_mode = self.client_mode(client_idx)
                client_mode_flag = self.client_mode_to_iperf3_flag(client_mode)
                client_future = executor.submit(
                    self.spawn_iperf3_client, client_idx, client_mode_flag
                )
                clients.append((client_mode, client_future))

            data = {"cpu_load_raw": cpu_load_future.result(), "g2h": [], "h2g": []}

            for mode, future in clients:
                data[mode].append(json.loads(future.result()))

            return data

    def client_mode(self, client_idx):
        """Converts client index into client mode"""
        match self._mode:
            case "g2h":
                client_mode = "g2h"
            case "h2g":
                client_mode = "h2g"
            case "bd":
                # in bidirectional mode we alternate
                # modes
                if client_idx % 2 == 0:
                    client_mode = "g2h"
                else:
                    client_mode = "h2g"
        return client_mode

    @staticmethod
    def client_mode_to_iperf3_flag(client_mode):
        """Converts client mode into iperf3 mode flag"""
        match client_mode:
            case "g2h":
                client_mode_flag = ""
            case "h2g":
                client_mode_flag = "-R"
        return client_mode_flag

    def spawn_iperf3_client(self, client_idx, client_mode_flag):
        """
        Spawns an iperf3 client within the guest. The `client_idx` determines what direction data should flow
        for this particular client (e.g. client-to-server or server-to-client)
        """

        # Add the port where the iperf3 client is going to send/receive.
        cmd = (
            self.guest_command(client_idx)
            .with_arg(client_mode_flag)
            .with_arg("--affinity", client_idx % self._microvm.vcpus_count)
            .build()
        )

        return self._microvm.ssh.check_output(cmd).stdout

    def host_command(self, port_offset):
        """Builds the command used for spawning an iperf3 server on the host"""
        return (
            CmdBuilder(self._iperf)
            .with_arg("-sD")
            .with_arg("-p", self._base_port + port_offset)
            .with_arg("-1")
        )

    def guest_command(self, port_offset):
        """Builds the command used for spawning an iperf3 client in the guest"""
        cmd = (
            CmdBuilder(self._guest_iperf)
            .with_arg("--time", self._runtime)
            .with_arg("--json")
            .with_arg("--omit", self._omit)
            .with_arg("-p", self._base_port + port_offset)
            .with_arg("--client", self._connect_to)
        )

        if self._payload_length != "DEFAULT":
            return cmd.with_arg("--len", self._payload_length)
        return cmd


def emit_iperf3_metrics(metrics, iperf_result, omit):
    """Consume the iperf3 data produced by the tcp/vsock throughput performance tests"""
    cpu_util = iperf_result["cpu_load_raw"]
    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")

    data_points = zip(
        *[time_series["intervals"][omit:] for time_series in iperf_result["g2h"]]
    )

    for point_in_time in data_points:
        metrics.put_metric(
            "throughput_guest_to_host",
            sum(interval["sum"]["bits_per_second"] for interval in point_in_time),
            "Bits/Second",
        )

    data_points = zip(
        *[time_series["intervals"][omit:] for time_series in iperf_result["h2g"]]
    )

    for point_in_time in data_points:
        metrics.put_metric(
            "throughput_host_to_guest",
            sum(interval["sum"]["bits_per_second"] for interval in point_in_time),
            "Bits/Second",
        )
