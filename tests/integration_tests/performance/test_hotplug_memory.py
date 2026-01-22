# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Tests for verifying the virtio-mem is working correctly

This file also contains functional tests for virtio-mem because they need to be
run on an ag=1 host due to the use of HugePages.
"""

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, wait_fixed

from framework.guest_stats import MeminfoGuest
from framework.microvm import HugePagesConfig, SnapshotType
from framework.properties import global_props
from framework.utils import get_resident_memory, supports_hugetlbfs_discard

MEMHP_BOOTARGS = "console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"
DEFAULT_CONFIG = {"total_size_mib": 1024, "slot_size_mib": 128, "block_size_mib": 2}


def uvm_booted_memhp(
    uvm,
    rootfs,
    _microvm_factory,
    vhost_user,
    memhp_config,
    huge_pages,
    _uffd_handler,
    snapshot_type,
):
    """Boots a VM with the given memory hotplugging config"""

    uvm.spawn()
    uvm.memory_monitor = None
    uvm_config = {
        "boot_args": MEMHP_BOOTARGS,
        "huge_pages": huge_pages,
        # we need enough memory to be able to hotplug up to 16GB
        "mem_size_mib": 512,
    }
    if vhost_user:
        # We need to setup ssh keys manually because we did not specify rootfs
        # in microvm_factory.build method
        ssh_key = rootfs.with_suffix(".id_rsa")
        uvm.ssh_key = ssh_key
        uvm.basic_config(
            **uvm_config,
            add_root_device=False,
            track_dirty_pages=(
                snapshot_type.needs_dirty_page_tracking if snapshot_type else False
            ),
        )
        uvm.add_vhost_user_drive(
            "rootfs", rootfs, is_root_device=True, is_read_only=True
        )
    else:
        uvm.basic_config(**uvm_config)

    uvm.api.memory_hotplug.put(**memhp_config)
    uvm.add_net_iface()
    uvm.start()
    return uvm


def uvm_resumed_memhp(
    uvm_plain,
    rootfs,
    microvm_factory,
    vhost_user,
    memhp_config,
    huge_pages,
    uffd_handler,
    snapshot_type,
):
    """Restores a VM with the given memory hotplugging config after booting and snapshotting"""
    if vhost_user:
        pytest.skip("vhost-user doesn't support snapshot/restore")
    if huge_pages and huge_pages != HugePagesConfig.NONE and not uffd_handler:
        pytest.skip("Hugepages requires a UFFD handler")
    uvm = uvm_booted_memhp(
        uvm_plain,
        rootfs,
        microvm_factory,
        vhost_user,
        memhp_config,
        huge_pages,
        None,
        snapshot_type,
    )
    snapshot = uvm.make_snapshot(snapshot_type)
    uvm2 = microvm_factory.build_from_snapshot(snapshot, uffd_handler_name=uffd_handler)
    uvm2.memory_monitor = None

    return uvm2


@pytest.fixture(
    params=[
        (uvm_booted_memhp, False, HugePagesConfig.NONE, None, None),
        (uvm_booted_memhp, False, HugePagesConfig.HUGETLBFS_2MB, None, None),
        (uvm_booted_memhp, True, HugePagesConfig.NONE, None, None),
        (uvm_resumed_memhp, False, HugePagesConfig.NONE, None, SnapshotType.FULL),
        (uvm_resumed_memhp, False, HugePagesConfig.NONE, None, SnapshotType.DIFF),
        (
            uvm_resumed_memhp,
            False,
            HugePagesConfig.NONE,
            None,
            SnapshotType.DIFF_MINCORE,
        ),
        (
            uvm_resumed_memhp,
            False,
            HugePagesConfig.NONE,
            "on_demand",
            SnapshotType.FULL,
        ),
        (
            uvm_resumed_memhp,
            False,
            HugePagesConfig.HUGETLBFS_2MB,
            "on_demand",
            SnapshotType.FULL,
        ),
    ],
    ids=[
        "booted",
        "booted-huge-pages",
        "booted-vhost-user",
        "resumed",
        "resumed-diff",
        "resumed-mincore",
        "resumed-uffd",
        "resumed-uffd-huge-pages",
    ],
)
def uvm_any_memhp(request, uvm_plain_6_1, rootfs, microvm_factory):
    """Fixture that yields a booted or resumed VM with memory hotplugging"""
    ctor, vhost_user, huge_pages, uffd_handler, snapshot_type = request.param
    yield ctor(
        uvm_plain_6_1,
        rootfs,
        microvm_factory,
        vhost_user,
        DEFAULT_CONFIG,
        huge_pages,
        uffd_handler,
        snapshot_type,
    )


def validate_metrics(uvm):
    """Validates that there are no fails in the metrics"""
    metrics_to_check = ["plug_fails", "unplug_fails", "unplug_all_fails", "state_fails"]
    if supports_hugetlbfs_discard():
        metrics_to_check.append("unplug_discard_fails")
    uvm.flush_metrics()
    for metrics in uvm.get_all_metrics():
        for k in metrics_to_check:
            assert (
                metrics["memory_hotplug"][k] == 0
            ), f"{k}={metrics[k]} is greater than zero"


def check_device_detected(uvm):
    """
    Check that the guest kernel has enabled virtio-mem.
    """
    hp_config = uvm.api.memory_hotplug.get().json()
    _, stdout, _ = uvm.ssh.check_output("dmesg | grep 'virtio_mem'")
    for line in stdout.splitlines():
        _, key, value = line.strip().split(":")
        key = key.strip()
        value = int(value.strip(), base=0)
        match key:
            case "start address":
                assert value >= (512 << 30), "start address isn't in past MMIO64 region"
            case "region size":
                assert (
                    value == hp_config["total_size_mib"] << 20
                ), "region size doesn't match"
            case "device block size":
                assert (
                    value == hp_config["block_size_mib"] << 20
                ), "block size doesn't match"
            case "plugged size":
                assert value == 0, "plugged size doesn't match"
            case "requested size":
                assert value == 0, "requested size doesn't match"
            case _:
                continue


def check_memory_usable(uvm):
    """Allocates memory to verify it's usable (5% margin to avoid OOM-kill)"""
    mem_available = MeminfoGuest(uvm).get().mem_available.mib()
    # try to allocate 95% of available memory
    amount_mib = int(mem_available * 95 / 100)

    _ = uvm.ssh.check_output(f"/usr/local/bin/fillmem {amount_mib}", timeout=30)
    # verify the allocation was successful
    _ = uvm.ssh.check_output("cat /tmp/fillmem_output.txt | grep successful")


def check_hotplug(uvm, requested_size_mib):
    """Verifies memory can be hot(un)plugged"""
    meminfo = MeminfoGuest(uvm)
    mem_total_fixed = (
        meminfo.get().mem_total.mib()
        - uvm.api.memory_hotplug.get().json()["plugged_size_mib"]
    )
    uvm.hotplug_memory(requested_size_mib)

    # verify guest driver received the request
    _, stdout, _ = uvm.ssh.check_output(
        "dmesg | grep 'virtio_mem' | grep 'requested size' | tail -1"
    )
    assert (
        int(stdout.strip().split(":")[-1].strip(), base=0) == requested_size_mib << 20
    )

    for attempt in Retrying(
        retry=retry_if_exception_type(AssertionError),
        stop=stop_after_delay(5),
        wait=wait_fixed(1),
        reraise=True,
    ):
        with attempt:
            # verify guest driver executed the request
            mem_total_after = meminfo.get().mem_total.mib()
            assert mem_total_after == mem_total_fixed + requested_size_mib


def check_hotunplug(uvm, requested_size_mib):
    """Verifies memory can be hotunplugged and gets released"""

    rss_before = get_resident_memory(uvm.ps)

    check_hotplug(uvm, requested_size_mib)

    rss_after = get_resident_memory(uvm.ps)

    print(f"RSS before: {rss_before}, after: {rss_after}")

    huge_pages = HugePagesConfig(uvm.api.machine_config.get().json()["huge_pages"])
    if huge_pages == HugePagesConfig.HUGETLBFS_2MB and supports_hugetlbfs_discard():
        assert rss_after < rss_before, "RSS didn't decrease"


def test_virtio_mem_hotplug_hotunplug(uvm_any_memhp):
    """
    Check that memory can be hotplugged into the VM.
    """
    uvm = uvm_any_memhp
    check_device_detected(uvm)

    check_hotplug(uvm, 1024)
    check_memory_usable(uvm)

    check_hotunplug(uvm, 0)

    # Check it works again
    check_hotplug(uvm, 1024)
    check_memory_usable(uvm)

    validate_metrics(uvm)


@pytest.mark.parametrize(
    "memhp_config",
    [
        {"total_size_mib": 256, "slot_size_mib": 128, "block_size_mib": 64},
        {"total_size_mib": 256, "slot_size_mib": 128, "block_size_mib": 128},
        {"total_size_mib": 256, "slot_size_mib": 256, "block_size_mib": 64},
        {"total_size_mib": 256, "slot_size_mib": 256, "block_size_mib": 256},
    ],
    ids=["all_different", "slot_sized_block", "single_slot", "single_block"],
)
def test_virtio_mem_configs(uvm_plain_6_1, memhp_config):
    """
    Check that the virtio mem device is working as expected for different configs
    """
    uvm = uvm_booted_memhp(
        uvm_plain_6_1, None, None, False, memhp_config, None, None, None
    )
    if not uvm.pci_enabled:
        pytest.skip(
            "Skip tests on MMIO transport to save time as we don't expect any difference."
        )

    check_device_detected(uvm)

    for size in range(
        0, memhp_config["total_size_mib"] + 1, memhp_config["block_size_mib"]
    ):
        check_hotplug(uvm, size)

    check_memory_usable(uvm)

    for size in range(
        memhp_config["total_size_mib"] - memhp_config["block_size_mib"],
        -1,
        -memhp_config["block_size_mib"],
    ):
        check_hotunplug(uvm, size)

    validate_metrics(uvm)


def test_snapshot_restore_persistence(uvm_plain_6_1, microvm_factory, snapshot_type):
    """
    Check that hptplugged memory is persisted across snapshot/restore.
    """
    if not uvm_plain_6_1.pci_enabled:
        pytest.skip(
            "Skip tests on MMIO transport to save time as we don't expect any difference."
        )
    uvm = uvm_booted_memhp(
        uvm_plain_6_1,
        None,
        microvm_factory,
        False,
        DEFAULT_CONFIG,
        None,
        None,
        snapshot_type,
    )

    uvm.hotplug_memory(1024)

    # Increase /dev/shm size as it defaults to half of the boot memory
    uvm.ssh.check_output("mount -o remount,size=1024M -t tmpfs tmpfs /dev/shm")

    uvm.ssh.check_output("dd if=/dev/urandom of=/dev/shm/mem_hp_test bs=1M count=1024")

    _, checksum_before, _ = uvm.ssh.check_output("sha256sum /dev/shm/mem_hp_test")

    snapshot = uvm.make_snapshot(snapshot_type)
    restored_vm = microvm_factory.build_from_snapshot(snapshot)

    _, checksum_after, _ = restored_vm.ssh.check_output(
        "sha256sum /dev/shm/mem_hp_test"
    )

    assert checksum_before == checksum_after, "Checksums didn't match"

    validate_metrics(restored_vm)


def test_snapshot_restore_incremental(uvm_plain_6_1, microvm_factory):
    """
    Check that hptplugged memory is persisted across snapshot/restore.
    """
    if not uvm_plain_6_1.pci_enabled:
        pytest.skip(
            "Skip tests on MMIO transport to save time as we don't expect any difference."
        )

    uvm = uvm_booted_memhp(
        uvm_plain_6_1, None, microvm_factory, False, DEFAULT_CONFIG, None, None, None
    )

    snapshot = uvm.snapshot_full()

    hotplug_count = 16
    hp_mem_mib_per_cycle = 1024 // hotplug_count
    checksums = []
    for i, uvm in enumerate(
        microvm_factory.build_n_from_snapshot(
            snapshot,
            hotplug_count + 1,
            incremental=True,
            use_snapshot_editor=True,
        )
    ):
        uvm.memory_monitor = None

        # check checksums of previous cycles
        for j in range(i):
            _, checksum, _ = uvm.ssh.check_output(f"sha256sum /dev/shm/mem_hp_test_{j}")
            assert checksum == checksums[j], f"Checksums didn't match for i={i} j={j}"

        # we run hotplug_count+1 uvms to check all the checksums at the end
        if i >= hotplug_count:
            continue

        total_hp_mem_mib = hp_mem_mib_per_cycle * (i + 1)
        uvm.hotplug_memory(total_hp_mem_mib)

        # Increase /dev/shm size as it defaults to half of the boot memory
        uvm.ssh.check_output(
            f"mount -o remount,size={total_hp_mem_mib}M -t tmpfs tmpfs /dev/shm"
        )

        uvm.ssh.check_output(
            f"dd if=/dev/urandom of=/dev/shm/mem_hp_test_{i} bs=1M count={hp_mem_mib_per_cycle}"
        )

        _, checksum, _ = uvm.ssh.check_output(f"sha256sum /dev/shm/mem_hp_test_{i}")
        checksums.append(checksum)

        validate_metrics(uvm)


def timed_memory_hotplug(uvm, size, metrics, metric_prefix, fc_metric_name):
    """Wait for all memory hotplug events to be processed"""

    uvm.flush_metrics()

    # poll every 5ms to check completion as the fastest hotplug is around 30ms
    api_time, total_time = uvm.hotplug_memory(size, poll=0.005)

    fc_metrics = uvm.flush_metrics()

    metrics.put_metric(
        f"{metric_prefix}_api_time",
        api_time,
        unit="Seconds",
    )
    metrics.put_metric(
        f"{metric_prefix}_total_time",
        total_time,
        unit="Seconds",
    )
    metrics.put_metric(
        f"{metric_prefix}_fc_time",
        fc_metrics["memory_hotplug"][fc_metric_name]["sum_us"],
        unit="Microseconds",
    )


@pytest.mark.nonci
@pytest.mark.parametrize(
    "hotplug_size",
    [
        1024,
        2048,
        4096,
        8192,
        16384,
    ],
)
@pytest.mark.parametrize(
    "huge_pages",
    [HugePagesConfig.NONE, HugePagesConfig.HUGETLBFS_2MB],
)
def test_memory_hotplug_latency(
    microvm_factory, guest_kernel_linux_6_1, rootfs, hotplug_size, huge_pages, metrics
):
    """Test the latency of hotplugging memory"""

    for i in range(20):
        config = {
            "total_size_mib": hotplug_size,
            "slot_size_mib": 128,
            "block_size_mib": 2,
        }
        uvm_plain_6_1 = microvm_factory.build(guest_kernel_linux_6_1, rootfs, pci=True)
        uvm = uvm_booted_memhp(
            uvm_plain_6_1, None, None, False, config, None, None, None
        )

        if i == 0:
            metrics.set_dimensions(
                {
                    "instance": global_props.instance,
                    "cpu_model": global_props.cpu_model,
                    "host_kernel": f"linux-{global_props.host_linux_version}",
                    "performance_test": "test_memory_hotplug_latency",
                    "hotplug_size": str(hotplug_size),
                    "huge_pages": huge_pages,
                    **uvm.dimensions,
                }
            )

        timed_memory_hotplug(uvm, hotplug_size, metrics, "hotplug", "plug_agg")
        timed_memory_hotplug(uvm, 0, metrics, "hotunplug", "unplug_agg")
        timed_memory_hotplug(uvm, hotplug_size, metrics, "hotplug_2nd", "plug_agg")
