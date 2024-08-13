# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the VSOCK throughput of Firecracker uVMs."""

import os

import pytest

from framework.utils_iperf import IPerf3Test, emit_iperf3_metrics
from framework.utils_vsock import VSOCK_UDS_PATH, make_host_port_path


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
        # The rootfs does not have iperf3-vsock
        iperf3_guest = "/tmp/iperf3-vsock"

        self._microvm.ssh.scp_put(self._iperf, iperf3_guest)
        self._guest_iperf = iperf3_guest
        return super().spawn_iperf3_client(client_idx, client_mode_flag)

    def guest_command(self, port_offset):
        return super().guest_command(port_offset).with_arg("--vsock")


@pytest.mark.timeout(120)
@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("payload_length", ["64K", "1024K"], ids=["p64K", "p1024K"])
@pytest.mark.parametrize("mode", ["g2h", "h2g", "bd"])
def test_vsock_throughput(
    microvm_factory, guest_kernel, rootfs, vcpus, payload_length, mode, metrics
):
    """
    Test vsock throughput for multiple vm configurations.
    """
    # We run bi-directional tests only on uVM with more than 2 vCPus
    # because we need to pin one iperf3/direction per vCPU, and since we
    # have two directions, we need at least two vCPUs.
    if mode == "bd" and vcpus < 2:
        pytest.skip("bidrectional test only done with at least 2 vcpus")

    mem_size_mib = 1024
    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
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

    emit_iperf3_metrics(metrics, data, VsockIPerf3Test.WARMUP_SEC)
