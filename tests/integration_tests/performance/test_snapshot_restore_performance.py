# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""

import os
import json
import logging
import tempfile

import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import (
    ArtifactCollection,
    ArtifactSet,
    create_net_devices_configuration,
)
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.matrix import TestContext, TestMatrix
from framework.stats import core
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import get_kernel_version, DictQuery
from framework.utils_cpuid import get_cpu_model_name, get_instance_type
import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error
import framework.stats as st
from integration_tests.performance.configs import defs
from integration_tests.performance.utils import handle_failure

TEST_ID = "snap_restore_performance"
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, get_kernel_version(level=1))
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG_DICT = json.load(open(CONFIG_NAME_ABS, encoding="utf-8"))

DEBUG = False
BASE_VCPU_COUNT = 1
BASE_MEM_SIZE_MIB = 128
BASE_NET_COUNT = 1
BASE_BLOCK_COUNT = 1
USEC_IN_MSEC = 1000

# Measurements tags.
RESTORE_LATENCY = "latency"

# Define 4 net device configurations.
net_ifaces = create_net_devices_configuration(4)

# We are using this as a global variable in order to only
# have to call the constructor and destructor once.
# pylint: disable=C0103
scratch_drives = []


# pylint: disable=R0903
class SnapRestoreBaselinesProvider(BaselineProvider):
    """Baselines provider for snapshot restore latency."""

    def __init__(self, env_id, workload):
        """Snapshot baseline provider initialization."""
        cpu_model_name = get_cpu_model_name()
        baselines = list(
            filter(
                lambda cpu_baseline: cpu_baseline["model"] == cpu_model_name,
                CONFIG_DICT["hosts"]["instances"][get_instance_type()]["cpus"],
            )
        )

        super().__init__(DictQuery({}))
        if len(baselines) > 0:
            super().__init__(DictQuery(baselines[0]))

        self._tag = "baselines/{}/" + env_id + "/{}/" + workload

    def get(self, ms_name: str, st_name: str) -> dict:
        """Return the baseline value corresponding to the key."""
        key = self._tag.format(ms_name, st_name)
        baseline = self._baselines.get(key)
        if baseline:
            target = baseline.get("target")
            delta_percentage = baseline.get("delta_percentage")
            return {
                "target": target,
                "delta": delta_percentage * target / 100,
            }
        return None


def construct_scratch_drives():
    """Create an array of scratch disks."""
    scratchdisks = ["vdb", "vdc", "vdd", "vde"]
    disk_files = [
        drive_tools.FilesystemFile(tempfile.mktemp(), size=64) for _ in scratchdisks
    ]
    return list(zip(scratchdisks, disk_files))


def default_lambda_consumer(env_id, workload):
    """Create a default lambda consumer for the snapshot restore test."""
    return st.consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            CONFIG_DICT["measurements"], SnapRestoreBaselinesProvider(env_id, workload)
        ),
        func=consume_output,
        func_kwargs={},
    )


def get_snap_restore_latency(
    context, vcpus, mem_size, nets=1, blocks=1, all_devices=False, iterations=10
):
    """Restore snapshots with various configs to measure latency."""
    vm_builder = context.custom["builder"]
    logger = context.custom["logger"]
    balloon = vsock = 1 if all_devices else 0
    microvm_spec = f"{vcpus}vcpu_{mem_size}mb_{nets}net_{blocks}block_{vsock}vsock_{balloon}balloon"

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()

    ifaces = None
    if nets > 1:
        ifaces = net_ifaces[:nets]

    # Create a fresh microvm from artifacts.
    vm_instance = vm_builder.build(
        kernel=context.kernel,
        disks=[rw_disk],
        ssh_key=ssh_key,
        config=context.microvm,
        net_ifaces=ifaces,
        use_ramdisk=True,
        io_engine="Sync",
    )
    basevm = vm_instance.vm
    response = basevm.machine_cfg.put(
        vcpu_count=vcpus,
        mem_size_mib=mem_size,
    )
    assert basevm.api_session.is_status_no_content(response.status_code)

    extra_disk_paths = []
    if blocks > 1:
        for (name, diskfile) in scratch_drives[: (blocks - 1)]:
            basevm.add_drive(name, diskfile.path, use_ramdisk=True, io_engine="Sync")
            extra_disk_paths.append(diskfile.path)
        assert len(extra_disk_paths) > 0

    if all_devices:
        response = basevm.balloon.put(
            amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
        )
        assert basevm.api_session.is_status_no_content(response.status_code)

        response = basevm.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/v.sock")
        assert basevm.api_session.is_status_no_content(response.status_code)

    basevm.start()

    logger.info(
        'Testing with microvm: "{}", kernel {}, disk {}'.format(
            microvm_spec, context.kernel.name(), context.disk.name()
        )
    )
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)
    full_snapshot = snapshot_builder.create(
        [rw_disk.local_path()] + extra_disk_paths,
        ssh_key,
        SnapshotType.FULL,
        net_ifaces=ifaces,
        use_ramdisk=True,
    )
    basevm.kill()
    values = []
    for _ in range(iterations):
        microvm, metrics_fifo = vm_builder.build_from_snapshot(
            full_snapshot, resume=True, use_ramdisk=True
        )
        # Attempt to connect to resumed microvm.
        ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
        # Check if guest still runs commands.
        exit_code, _, _ = ssh_connection.execute_command("dmesg")
        assert exit_code == 0

        value = 0
        # Parse all metric data points in search of load_snapshot time.
        metrics = microvm.get_all_metrics(metrics_fifo)
        for data_point in metrics:
            metrics = json.loads(data_point)
            cur_value = metrics["latencies_us"]["load_snapshot"]
            if cur_value > 0:
                value = cur_value / USEC_IN_MSEC
                break
        values.append(value)
        microvm.kill()
        microvm.jailer.cleanup()

    full_snapshot.cleanup()
    basevm.jailer.cleanup()
    # The destructor is not called for the disk copy artifact.
    rw_disk.cleanup()
    result = {}
    result[RESTORE_LATENCY] = values
    return result


def consume_output(cons, result):
    """Consumer function."""
    restore_latency = result[RESTORE_LATENCY]
    for value in restore_latency:
        cons.consume_data(RESTORE_LATENCY, value)


@pytest.mark.nonci
@pytest.mark.timeout(300 * 1000)  # 1.40 hours
@pytest.mark.parametrize("results_file_dumper", [CONFIG_NAME_ABS], indirect=True)
def test_snap_restore_performance(bin_cloner_path, results_file_dumper):
    """
    Test the performance of snapshot restore.

    @type: performance
    """
    logger = logging.getLogger(TEST_ID)
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_1024mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    logger.info("Testing on processor %s", get_cpu_model_name())

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "logger": logger,
        "name": TEST_ID,
        "results_file_dumper": results_file_dumper,
        "workload": "restore",
    }

    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )
    test_matrix.run_test(snapshot_workload)


def snapshot_scaling_vcpus(context, st_core, vcpu_count=10):
    """Restore snapshots with variable vcpu count."""
    workload = context.custom["workload"]
    for i in range(vcpu_count):
        env_id = (
            f"{context.kernel.name()}/{context.disk.name()}/"
            f"{BASE_VCPU_COUNT + i}vcpu_{BASE_MEM_SIZE_MIB}mb"
        )

        st_prod = st.producer.LambdaProducer(
            func=get_snap_restore_latency,
            func_kwargs={
                "context": context,
                "vcpus": BASE_VCPU_COUNT + i,
                "mem_size": BASE_MEM_SIZE_MIB,
            },
        )
        st_cons = default_lambda_consumer(env_id, workload)
        st_core.add_pipe(st_prod, st_cons, f"{env_id}/{workload}")


def snapshot_scaling_mem(context, st_core, mem_exponent=9):
    """Restore snapshots with variable memory size."""
    workload = context.custom["workload"]
    for i in range(1, mem_exponent):
        env_id = (
            f"{context.kernel.name()}/{context.disk.name()}/"
            f"{BASE_VCPU_COUNT}vcpu_{BASE_MEM_SIZE_MIB * (2 ** i)}mb"
        )

        st_prod = st.producer.LambdaProducer(
            func=get_snap_restore_latency,
            func_kwargs={
                "context": context,
                "vcpus": BASE_VCPU_COUNT,
                "mem_size": BASE_MEM_SIZE_MIB * (2**i),
            },
        )
        st_cons = default_lambda_consumer(env_id, workload)
        st_core.add_pipe(st_prod, st_cons, f"{env_id}/{workload}")


def snapshot_scaling_net(context, st_core, net_count=4):
    """Restore snapshots with variable net device count."""
    workload = context.custom["workload"]
    for i in range(1, net_count):
        env_id = (
            f"{context.kernel.name()}/{context.disk.name()}/"
            f"{BASE_NET_COUNT + i}net_dev"
        )

        st_prod = st.producer.LambdaProducer(
            func=get_snap_restore_latency,
            func_kwargs={
                "context": context,
                "vcpus": BASE_VCPU_COUNT,
                "mem_size": BASE_MEM_SIZE_MIB,
                "nets": BASE_NET_COUNT + i,
            },
        )
        st_cons = default_lambda_consumer(env_id, workload)
        st_core.add_pipe(st_prod, st_cons, f"{env_id}/{workload}")


def snapshot_scaling_block(context, st_core, block_count=4):
    """Restore snapshots with variable block device count."""
    # pylint: disable=W0603
    workload = context.custom["workload"]
    global scratch_drives
    scratch_drives = construct_scratch_drives()

    for i in range(1, block_count):
        env_id = (
            f"{context.kernel.name()}/{context.disk.name()}/"
            f"{BASE_BLOCK_COUNT + i}block_dev"
        )

        st_prod = st.producer.LambdaProducer(
            func=get_snap_restore_latency,
            func_kwargs={
                "context": context,
                "vcpus": BASE_VCPU_COUNT,
                "mem_size": BASE_MEM_SIZE_MIB,
                "blocks": BASE_BLOCK_COUNT + i,
            },
        )
        st_cons = default_lambda_consumer(env_id, workload)
        st_core.add_pipe(st_prod, st_cons, f"{env_id}/{workload}")


def snapshot_all_devices(context, st_core):
    """Restore snapshots with one of each devices."""
    workload = context.custom["workload"]
    env_id = f"{context.kernel.name()}/{context.disk.name()}/" f"all_dev"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "context": context,
            "vcpus": BASE_VCPU_COUNT,
            "mem_size": BASE_MEM_SIZE_MIB,
            "all_devices": True,
        },
    )
    st_cons = default_lambda_consumer(env_id, workload)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{workload}")


def snapshot_workload(context):
    """Test all VM configurations for snapshot restore."""
    file_dumper = context.custom["results_file_dumper"]

    st_core = core.Core(
        name=TEST_ID, iterations=1, custom={"cpu_model_name": get_cpu_model_name()}
    )

    snapshot_scaling_vcpus(context, st_core, vcpu_count=10)
    snapshot_scaling_mem(context, st_core, mem_exponent=9)
    snapshot_scaling_net(context, st_core)
    snapshot_scaling_block(context, st_core)
    snapshot_all_devices(context, st_core)

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(file_dumper, err)

    file_dumper.dump(result)
