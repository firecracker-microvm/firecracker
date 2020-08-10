# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import json
import logging
import os
import platform
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
import host_tools.network as net_tools  # pylint: disable=import-error
import host_tools.logging as log_tools


# How many latencies do we sample per test.
SAMPLE_COUNT = 3
USEC_IN_MSEC = 1000

# Latencies in milliseconds.
CREATE_LATENCY_BASELINES = {
    '2vcpu_256mb.json': {
        'FULL':  1000,
        'DIFF':  0,
    },
    '2vcpu_512mb.json': {
        'FULL':  1000,
        'DIFF':  0,
    }
}

# The latencies are pretty high during integration tests and
# this is tracked here:
# https://github.com/firecracker-microvm/firecracker/issues/2027
# TODO: Update the table after fix. Target is < 5ms.
LOAD_LATENCY_BASELINES = {
    '2vcpu_256mb.json': 8,
    '2vcpu_512mb.json': 8,
}


def _test_snapshot_create_latency(context):
    logger = context.custom['logger']
    vm_builder = context.custom['builder']
    snapshot_type = context.custom['snapshot_type']
    enable_diff_snapshots = snapshot_type == SnapshotType.DIFF

    logger.info("""Measuring snapshot create({}) latency for microvm: \"{}\",
kernel {}, disk {} """.format(snapshot_type,
                              context.microvm.name(),
                              context.kernel.name(),
                              context.disk.name()))

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()

    # Measure a burst of snapshot create calls.
    for i in range(SAMPLE_COUNT):
        # Create a fresh microvm from aftifacts.
        vm = vm_builder.build(kernel=context.kernel,
                              disks=[rw_disk],
                              ssh_key=ssh_key,
                              config=context.microvm,
                              enable_diff_snapshots=enable_diff_snapshots)

        # Configure metrics system.
        metrics_fifo_path = os.path.join(vm.path, 'metrics_fifo')
        metrics_fifo = log_tools.Fifo(metrics_fifo_path)

        response = vm.metrics.put(
            metrics_path=vm.create_jailed_resource(metrics_fifo.path)
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        vm.start()

        # Create a snapshot builder from a microvm.
        snapshot_builder = SnapshotBuilder(vm)
        snapshot_builder.create([rw_disk],
                                ssh_key,
                                snapshot_type)
        metrics = vm.flush_metrics(metrics_fifo)

        if snapshot_type == SnapshotType.FULL:
            value = metrics['latencies_us']['full_create_snapshot']
            baseline = CREATE_LATENCY_BASELINES[context.microvm.name()]['FULL']
        else:
            value = metrics['latencies_us']['diff_create_snapshot']
            baseline = CREATE_LATENCY_BASELINES[context.microvm.name()]['DIFF']

        value = value / USEC_IN_MSEC

        assert baseline > value, "CreateSnapshot latency degraded."

        logger.info("Latency {}/3: {} ms".format(i + 1, value))
        vm.kill()


def _test_snapshot_resume_latency(context):
    logger = context.custom['logger']
    vm_builder = context.custom['builder']
    snapshot_type = context.custom['snapshot_type']
    enable_diff_snapshots = snapshot_type == SnapshotType.DIFF

    logger.info("""Measuring snapshot resume({}) latency for microvm: \"{}\",
kernel {}, disk {} """.format(snapshot_type,
                              context.microvm.name(),
                              context.kernel.name(),
                              context.disk.name()))

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[rw_disk],
                              ssh_key=ssh_key,
                              config=context.microvm,
                              enable_diff_snapshots=enable_diff_snapshots)

    host_ip = None
    guest_ip = None
    netmask_len = None
    network_config = net_tools.UniqueIPv4Generator.instance()
    _, host_ip, guest_ip = basevm.ssh_network_config(network_config,
                                                     iface_id='1',
                                                     tapname="tap0")
    logger.debug("Host IP: {}, Guest IP: {}".format(host_ip, guest_ip))

    # # We will need netmask_len in build_from_snapshot() call later.
    netmask_len = network_config.get_netmask_len()
    basevm.start()
    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

    # Check if guest works.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0

    logger.info("Create {}.".format(snapshot_type))
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    snapshot = snapshot_builder.create([rw_disk.local_path()],
                                       ssh_key,
                                       snapshot_type)

    basevm.kill()

    for i in range(SAMPLE_COUNT):
        microvm, metrics_fifo = vm_builder.build_from_snapshot(
                                                snapshot,
                                                host_ip,
                                                guest_ip,
                                                netmask_len,
                                                True,
                                                enable_diff_snapshots)

        # Attempt to connect to resumed microvm.
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

        # Verify if guest can run commands.
        exit_code, _, _ = ssh_connection.execute_command("sync")
        assert exit_code == 0

        value = 0
        # Parse all metric data points in search of load_snapshot time.
        metrics = microvm.get_all_metrics(metrics_fifo)
        for data_point in metrics:
            metrics = json.loads(data_point)
            cur_value = metrics['latencies_us']['load_snapshot'] / USEC_IN_MSEC
            if cur_value > 0:
                value = cur_value
                break

        baseline = LOAD_LATENCY_BASELINES[context.microvm.name()]
        logger.info("Latency {}/{}: {} ms".format(i + 1, SAMPLE_COUNT, value))
        value = value / USEC_IN_MSEC
        assert baseline > value, "LoadSnapshot latency degraded."

        microvm.kill()


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_snapshot_create_latency(network_config,
                                 bin_cloner_path):
    """Test scenario: Snapshot create performance measurement."""
    logger = logging.getLogger("snapshot_sequence")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 256/512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_512mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="2vcpu_256mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels(keyword="4.14"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger,
        'snapshot_type': SnapshotType.FULL,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_test_snapshot_create_latency)


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_snapshot_resume_latency(network_config,
                                 bin_cloner_path):
    """Test scenario: Snapshot load performance measurement."""
    logger = logging.getLogger("snapshot_load")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 256/512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_512mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="2vcpu_256mb"))

    kernel_artifacts = ArtifactSet(artifacts.kernels(keyword="4.14"))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger,
        'snapshot_type': SnapshotType.FULL,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_test_snapshot_resume_latency)
