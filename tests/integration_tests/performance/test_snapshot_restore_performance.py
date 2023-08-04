# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""

import json
import tempfile
from functools import lru_cache

import pytest

import framework.stats as st
import host_tools.drive as drive_tools
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import get_kernel_version
from integration_tests.performance.configs import defs

TEST_ID = "snapshot_restore_performance"
WORKLOAD = "restore"
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, get_kernel_version(level=1))
CONFIG_NAME_ABS = defs.CFG_LOCATION / CONFIG_NAME_REL

BASE_VCPU_COUNT = 1
BASE_MEM_SIZE_MIB = 128
BASE_NET_COUNT = 1
BASE_BLOCK_COUNT = 1
USEC_IN_MSEC = 1000

# Measurements tags.
RESTORE_LATENCY = "latency"


# pylint: disable=R0903
class SnapRestoreBaselinesProvider(BaselineProvider):
    """Baselines provider for snapshot restore latency."""

    def __init__(self, env_id, workload, raw_baselines):
        """Snapshot baseline provider initialization."""
        super().__init__(raw_baselines)

        self._tag = "baselines/{}/" + env_id + "/{}/" + workload

    def get(self, metric_name: str, statistic_name: str) -> dict:
        """Return the baseline value corresponding to the key."""
        key = self._tag.format(metric_name, statistic_name)
        baseline = self._baselines.get(key)
        if baseline:
            target = baseline.get("target")
            delta_percentage = baseline.get("delta_percentage")
            return {
                "target": target,
                "delta": delta_percentage * target / 100,
            }
        return None


@lru_cache
def get_scratch_drives():
    """Create an array of scratch disks."""
    scratchdisks = ["vdb", "vdc", "vdd", "vde"]
    return [
        (drive, drive_tools.FilesystemFile(tempfile.mktemp(), size=64))
        for drive in scratchdisks
    ]


def default_lambda_consumer(env_id, workload):
    """Create a default lambda consumer for the snapshot restore test."""
    raw_baselines = json.loads(CONFIG_NAME_ABS.read_text("utf-8"))

    return st.consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            raw_baselines["measurements"],
            SnapRestoreBaselinesProvider(env_id, workload, raw_baselines),
        ),
        func=consume_output,
    )


def get_snap_restore_latency(
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpus,
    mem_size,
    nets=3,
    blocks=3,
    all_devices=False,
    iterations=30,
):
    """Restore snapshots with various configs to measure latency."""
    scratch_drives = get_scratch_drives()

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info")
    vm.basic_config(
        vcpu_count=vcpus,
        mem_size_mib=mem_size,
        rootfs_io_engine="Sync",
    )

    for _ in range(nets):
        vm.add_net_iface()

    if blocks > 1:
        for name, diskfile in scratch_drives[: (blocks - 1)]:
            vm.add_drive(name, diskfile.path, io_engine="Sync")

    if all_devices:
        vm.api.balloon.put(
            amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
        )
        vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/v.sock")

    vm.start()
    snapshot = vm.snapshot_full()
    vm.kill()

    values = []
    for _ in range(iterations):
        microvm = microvm_factory.build()
        microvm.spawn()
        microvm.restore_from_snapshot(snapshot, resume=True)
        # Check if guest still runs commands.
        exit_code, _, _ = microvm.ssh.run("dmesg")
        assert exit_code == 0

        value = 0
        # Parse all metric data points in search of load_snapshot time.
        microvm.flush_metrics()
        metrics = microvm.get_all_metrics()
        for data_point in metrics:
            cur_value = data_point["latencies_us"]["load_snapshot"]
            if cur_value > 0:
                value = cur_value / USEC_IN_MSEC
                break
        assert value > 0
        values.append(value)
        microvm.kill()

    snapshot.delete()
    return values


def consume_output(cons, latencies):
    """Consumer function."""
    for value in latencies:
        yield RESTORE_LATENCY, value, "Milliseconds"
        cons.consume_data(RESTORE_LATENCY, value)


@pytest.mark.nonci
@pytest.mark.parametrize(
    "mem, vcpus",
    [
        (128, 1),
        (1024, 1),
        (2048, 2),
        (4096, 3),
        (6144, 4),
        (8192, 5),
        (10240, 6),
        (12288, 7),
    ],
)
def test_snapshot_scaling(microvm_factory, rootfs, guest_kernel, st_core, mem, vcpus):
    """
    Restores snapshots with vcpu/memory configuration, roughly scaling according to mem = (vcpus - 1) * 2048MB,
    which resembles firecracker production setups.
    """

    # The guest kernel does not "participate" in snapshot restore, so just pick some
    # arbitrary one
    if "4.14" not in guest_kernel.name:
        pytest.skip()

    guest_config = f"{vcpus}vcpu_{mem}mb"
    env_id = f"{st_core.env_id_prefix}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
            "vcpus": vcpus,
            "mem_size": mem,
        },
    )
    st_cons = default_lambda_consumer(env_id, WORKLOAD)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{WORKLOAD}")
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config
    st_core.run_exercise()


@pytest.mark.nonci
def test_snapshot_all_devices(microvm_factory, rootfs, guest_kernel, st_core):
    """Restore snapshots with one of each devices."""

    # The guest kernel does not "participate" in snapshot restore, so just pick some
    # arbitrary one
    if "4.14" not in guest_kernel.name:
        pytest.skip()

    guest_config = "all_dev"
    env_id = f"{st_core.env_id_prefix}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
            "nets": 1,
            "blocks": 1,
            "vcpus": BASE_VCPU_COUNT,
            "mem_size": BASE_MEM_SIZE_MIB,
            "all_devices": True,
        },
    )
    st_cons = default_lambda_consumer(env_id, WORKLOAD)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{WORKLOAD}")
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config
    st_core.run_exercise()
