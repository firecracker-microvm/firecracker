# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the VSOCK throughput of Firecracker uVMs."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from framework.utils_iperf import IPerf3Test, emit_iperf3_metrics
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    make_host_port_path,
    start_guest_echo_server,
)


class VsockIPerf3Test(IPerf3Test):
    """IPerf3 runner for the vsock throughput performance test"""

    BASE_PORT = 5201

    # How many clients/servers should be spawned per vcpu
    LOAD_FACTOR = 1

    # Time (in seconds) for which iperf "warms up"
    WARMUP_SEC = 3

    # Time (in seconds) for which iperf runs after warmup is done
    RUNTIME_SEC = 20

    # VM guest memory size
    GUEST_MEM_MIB = 1024

    def __init__(self, microvm, mode, payload_length):
        super().__init__(
            microvm,
            self.BASE_PORT,
            self.RUNTIME_SEC,
            self.WARMUP_SEC,
            mode,
            self.LOAD_FACTOR * microvm.vcpus_count,
            2,
            iperf="/usr/local/bin/iperf3-vsock",
            payload_length=payload_length,
        )
        # The rootfs does not have iperf3-vsock
        iperf3_guest = "/tmp/iperf3-vsock"

        self._microvm.ssh.scp_put(self._iperf, iperf3_guest)
        self._guest_iperf = iperf3_guest

    def host_command(self, port_offset):
        return (
            super()
            .host_command(port_offset)
            .with_arg("--vsock")
            .with_arg("-B", os.path.join(self._microvm.path, VSOCK_UDS_PATH))
        )

    def spawn_iperf3_client(self, client_idx, client_mode_flag):
        # Bind the UDS in the jailer's root.
        self._microvm.create_jailed_resource(
            os.path.join(
                self._microvm.path,
                make_host_port_path(VSOCK_UDS_PATH, self._base_port + client_idx),
            )
        )
        return super().spawn_iperf3_client(client_idx, client_mode_flag)

    def guest_command(self, port_offset):
        return super().guest_command(port_offset).with_arg("--vsock")


def consume_vsock_ping_output(ping_output):
    """Parse vsock_helper ping output.

    Output format:
    rtt=123.456 us seq=1
    rtt=234.567 us seq=2
    ...

    Yields RTT values in microseconds as floats.
    """
    pattern = r"rtt=([\d.]+) us seq=\d+"
    for line in ping_output.strip().split("\n"):
        match = re.match(pattern, line)
        if match:
            yield float(match.group(1))


@pytest.mark.timeout(120)
@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("payload_length", ["64K", "1024K"], ids=["p64K", "p1024K"])
@pytest.mark.parametrize("mode", ["g2h", "h2g"])
def test_vsock_throughput(
    uvm_plain_acpi,
    vcpus,
    payload_length,
    mode,
    metrics,
    results_dir,
):
    """
    Test vsock throughput for multiple vm configurations.
    """

    mem_size_mib = 1024
    vm = uvm_plain_acpi
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=mem_size_mib)
    vm.add_net_iface()
    # Create a vsock device
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_vsock_throughput",
            "payload_length": payload_length,
            "mode": mode,
            **vm.dimensions,
        }
    )

    vm.pin_threads(0)

    test = VsockIPerf3Test(vm, mode, payload_length)
    data = test.run_test(vm.vcpus_count + 2)

    for i, g2h in enumerate(data["g2h"]):
        Path(results_dir / f"g2h_{i}.json").write_text(
            json.dumps(g2h), encoding="utf-8"
        )
    for i, h2g in enumerate(data["h2g"]):
        Path(results_dir / f"h2g_{i}.json").write_text(
            json.dumps(h2g), encoding="utf-8"
        )

    emit_iperf3_metrics(metrics, data, VsockIPerf3Test.WARMUP_SEC)


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
def test_vsock_latency_g2h(uvm_plain_acpi, vcpus, metrics, bin_vsock_path):
    """
    Test VSOCK latency for guest-to-host connections.

    This starts an echo server on the host and measures RTT from
    the guest using the vsock_helper ping command.
    """
    rounds = 15
    requests_per_round = 30
    delay_sec = 0.01

    mem_size_mib = 1024
    vm = uvm_plain_acpi
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=mem_size_mib)
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_vsock_latency",
            "mode": "g2h",
            **vm.dimensions,
        }
    )

    vm.pin_threads(0)

    vm.ssh.scp_put(bin_vsock_path, "/tmp/vsock_helper")

    server_port_path = os.path.join(
        vm.path, make_host_port_path(VSOCK_UDS_PATH, ECHO_SERVER_PORT)
    )

    echo_server = subprocess.Popen(
        ["socat", f"UNIX-LISTEN:{server_port_path},fork,backlog=5", "exec:'/bin/cat'"]
    )

    try:
        for attempt in Retrying(
            wait=wait_fixed(0.2),
            stop=stop_after_attempt(5),
            reraise=True,
        ):
            with attempt:
                assert Path(server_port_path).exists()

        vm.create_jailed_resource(server_port_path)

        samples = []
        for _ in range(rounds):
            _, ping_output, _ = vm.ssh.check_output(
                f"/tmp/vsock_helper ping 2 {ECHO_SERVER_PORT} "
                f"{requests_per_round} {delay_sec}"
            )
            samples.extend(consume_vsock_ping_output(ping_output))

        for sample in samples:
            metrics.put_metric("vsock_ping_latency", sample, "Microseconds")

    finally:
        echo_server.terminate()
        rc = echo_server.wait()
        # socat exits with 128 + 15 (SIGTERM)
        assert rc == 143


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
def test_vsock_latency_h2g(uvm_plain_acpi, vcpus, metrics, bin_vsock_path):
    """
    Test VSOCK latency for host-to-guest connections.

    This starts an echo server in the guest and measures RTT from
    the host using the vsock_helper ping-uds command.
    """
    rounds = 15
    requests_per_round = 30
    delay_sec = 0.01

    mem_size_mib = 1024
    vm = uvm_plain_acpi
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=mem_size_mib)
    vm.add_net_iface()
    vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    vm.start()

    metrics.set_dimensions(
        {
            "performance_test": "test_vsock_latency",
            "mode": "h2g",
            **vm.dimensions,
        }
    )

    vm.pin_threads(0)

    uds_path = start_guest_echo_server(vm)

    samples = []
    for _ in range(rounds):
        result = subprocess.run(
            [
                bin_vsock_path,
                "ping-uds",
                uds_path,
                str(ECHO_SERVER_PORT),
                str(requests_per_round),
                str(delay_sec),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        samples.extend(consume_vsock_ping_output(result.stdout))

    for sample in samples:
        metrics.put_metric("vsock_ping_latency", sample, "Microseconds")
