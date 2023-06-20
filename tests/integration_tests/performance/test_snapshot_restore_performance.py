# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""

import json
import os
import tempfile
from functools import lru_cache

import pytest

import framework.stats as st
import host_tools.drive as drive_tools
from framework.artifacts import create_net_devices_configuration
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.utils import DictQuery, get_kernel_version
from integration_tests.performance.configs import defs

TEST_ID = "snapshot_restore_performance"
WORKLOAD = "restore"
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID, get_kernel_version(level=1))
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG_DICT = json.load(open(CONFIG_NAME_ABS, encoding="utf-8"))

BASE_VCPU_COUNT = 1
BASE_MEM_SIZE_MIB = 128
BASE_NET_COUNT = 1
BASE_BLOCK_COUNT = 1
USEC_IN_MSEC = 1000

# Measurements tags.
RESTORE_LATENCY = "latency"

# Define 4 net device configurations.
net_ifaces = create_net_devices_configuration(4)


# pylint: disable=R0903
class SnapRestoreBaselinesProvider(BaselineProvider):
    """Baselines provider for snapshot restore latency."""

    def __init__(self, env_id, workload):
        """Snapshot baseline provider initialization."""
        baseline = self.read_baseline(CONFIG_DICT)
        super().__init__(DictQuery(baseline))
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
    return st.consumer.LambdaConsumer(
        metadata_provider=DictMetadataProvider(
            CONFIG_DICT["measurements"], SnapRestoreBaselinesProvider(env_id, workload)
        ),
        func=consume_output,
        func_kwargs={},
    )


def get_snap_restore_latency(
    vm_builder,
    microvm_factory,
    guest_kernel,
    rootfs,
    vcpus,
    mem_size,
    nets=1,
    blocks=1,
    all_devices=False,
    iterations=10,
):
    """Restore snapshots with various configs to measure latency."""
    scratch_drives = get_scratch_drives()
    ifaces = net_ifaces[:nets]

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn(use_ramdisk=True, log_level="Info")
    vm.basic_config(
        vcpu_count=vcpus,
        mem_size_mib=mem_size,
        rootfs_io_engine="Sync",
        use_initrd=True,
    )

    for iface in ifaces:
        vm.create_tap_and_ssh_config(
            host_ip=iface.host_ip,
            guest_ip=iface.guest_ip,
            netmask_len=iface.netmask,
            tapname=iface.tap_name,
        )
        response = vm.network.put(
            iface_id=iface.dev_name,
            host_dev_name=iface.tap_name,
            guest_mac=iface.guest_mac,
        )
        assert vm.api_session.is_status_no_content(response.status_code)

    extra_disk_paths = []
    if blocks > 1:
        for name, diskfile in scratch_drives[: (blocks - 1)]:
            vm.add_drive(name, diskfile.path, use_ramdisk=True, io_engine="Sync")
            extra_disk_paths.append(diskfile.path)
        assert len(extra_disk_paths) > 0

    if all_devices:
        response = vm.balloon.put(
            amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        response = vm.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/v.sock")
        assert vm.api_session.is_status_no_content(response.status_code)

    vm.start()

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)
    full_snapshot = snapshot_builder.create(
        [vm.rootfs_file] + extra_disk_paths,
        rootfs.ssh_key(),
        SnapshotType.FULL,
        net_ifaces=ifaces,
        use_ramdisk=True,
    )
    vm.kill()
    values = []
    for _ in range(iterations):
        microvm, metrics_fifo = vm_builder.build_from_snapshot(
            full_snapshot, resume=True, use_ramdisk=True
        )
        # Check if guest still runs commands.
        exit_code, _, _ = microvm.ssh.execute_command("dmesg")
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
    vm.jailer.cleanup()
    return {RESTORE_LATENCY: values}


def consume_output(cons, result):
    """Consumer function."""
    restore_latency = result[RESTORE_LATENCY]
    for value in restore_latency:
        cons.consume_data(RESTORE_LATENCY, value)


@pytest.mark.nonci
@pytest.mark.parametrize("vcpu_count", [1, 2, 4, 8, 10])
def test_snapshot_scaling_vcpus(
    bin_cloner_path, microvm_factory, rootfs, guest_kernel, vcpu_count, st_core
):
    """Restore snapshots with variable vcpu count."""
    guest_config = f"{vcpu_count}vcpu_{BASE_MEM_SIZE_MIB}mb"
    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "vm_builder": MicrovmBuilder(bin_cloner_path),
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
            "vcpus": vcpu_count,
            "mem_size": BASE_MEM_SIZE_MIB,
        },
    )
    st_cons = default_lambda_consumer(env_id, WORKLOAD)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{WORKLOAD}")
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config
    st_core.run_exercise()


# exponent=8 takes around 400s seconds
@pytest.mark.nonci
@pytest.mark.timeout(10 * 60)
@pytest.mark.parametrize("mem_exponent", range(1, 9))
def test_snapshot_scaling_mem(
    bin_cloner_path, microvm_factory, rootfs, guest_kernel, mem_exponent, st_core
):
    """Restore snapshots with variable memory size."""
    mem_mib = BASE_MEM_SIZE_MIB * (2**mem_exponent)
    guest_config = f"{BASE_VCPU_COUNT}vcpu_{mem_mib}mb"
    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "vm_builder": MicrovmBuilder(bin_cloner_path),
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
            "vcpus": BASE_VCPU_COUNT,
            "mem_size": mem_mib,
        },
    )
    st_cons = default_lambda_consumer(env_id, WORKLOAD)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{WORKLOAD}")
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config
    st_core.run_exercise()


@pytest.mark.nonci
@pytest.mark.parametrize("net_count", range(1, 4))
def test_snapshot_scaling_net(
    bin_cloner_path, microvm_factory, rootfs, guest_kernel, st_core, net_count
):
    """Restore snapshots with variable net device count."""
    guest_config = f"{BASE_NET_COUNT + net_count}net_dev"
    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "vm_builder": MicrovmBuilder(bin_cloner_path),
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
            "vcpus": BASE_VCPU_COUNT,
            "mem_size": BASE_MEM_SIZE_MIB,
            "nets": BASE_NET_COUNT + net_count,
        },
    )
    st_cons = default_lambda_consumer(env_id, WORKLOAD)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{WORKLOAD}")
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config
    st_core.run_exercise()


@pytest.mark.nonci
@pytest.mark.parametrize("block_count", range(1, 4))
def test_snapshot_scaling_block(
    bin_cloner_path, microvm_factory, rootfs, guest_kernel, st_core, block_count
):
    """Restore snapshots with variable block device count."""
    guest_config = f"{BASE_BLOCK_COUNT + block_count}block_dev"
    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "vm_builder": MicrovmBuilder(bin_cloner_path),
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
            "vcpus": BASE_VCPU_COUNT,
            "mem_size": BASE_MEM_SIZE_MIB,
            "blocks": BASE_BLOCK_COUNT + block_count,
        },
    )
    st_cons = default_lambda_consumer(env_id, WORKLOAD)
    st_core.add_pipe(st_prod, st_cons, f"{env_id}/{WORKLOAD}")
    st_core.name = TEST_ID
    st_core.custom["guest_config"] = guest_config
    st_core.run_exercise()


@pytest.mark.nonci
def test_snapshot_all_devices(
    bin_cloner_path, microvm_factory, rootfs, guest_kernel, st_core
):
    """Restore snapshots with one of each devices."""
    guest_config = "all_dev"
    env_id = f"{guest_kernel.name()}/{rootfs.name()}/{guest_config}"
    st_prod = st.producer.LambdaProducer(
        func=get_snap_restore_latency,
        func_kwargs={
            "vm_builder": MicrovmBuilder(bin_cloner_path),
            "microvm_factory": microvm_factory,
            "guest_kernel": guest_kernel,
            "rootfs": rootfs,
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
