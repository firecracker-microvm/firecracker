# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /balloon resources."""

import logging
import time
from subprocess import TimeoutExpired

import pytest
import requests

from framework.guest_stats import MeminfoGuest
from framework.utils import get_resident_memory

STATS_POLLING_INTERVAL_S = 1


def get_stable_rss_mem(uvm, percentage_delta=1):
    """
    Get the RSS memory that a guest uses, given the pid of the guest.

    Wait till the fluctuations in RSS drop below percentage_delta.
    Or print a warning if this does not happen.
    """

    first_rss = 0
    second_rss = 0
    for _ in range(5):
        first_rss = get_resident_memory(uvm.ps)
        time.sleep(1)
        second_rss = get_resident_memory(uvm.ps)
        abs_diff = abs(first_rss - second_rss)
        abs_delta = abs_diff / first_rss * 100
        print(
            f"RSS readings (bytes): old: {first_rss} new: {second_rss} abs_diff: {abs_diff} abs_delta: {abs_delta}"
        )
        if abs_delta < percentage_delta:
            return second_rss

        time.sleep(1)

    print("WARNING: RSS readings did not stabilize")
    return second_rss


def lower_ssh_oom_chance(ssh_connection):
    """Lure OOM away from ssh process"""
    logger = logging.getLogger("lower_ssh_oom_chance")

    cmd = "cat /run/sshd.pid"
    exit_code, stdout, stderr = ssh_connection.run(cmd)
    # add something to the logs for troubleshooting
    if exit_code != 0:
        logger.error("while running: %s", cmd)
        logger.error("stdout: %s", stdout)
        logger.error("stderr: %s", stderr)

    for pid in stdout.split(" "):
        cmd = f"choom -n -1000 -p {pid}"
        exit_code, stdout, stderr = ssh_connection.run(cmd)
        if exit_code != 0:
            logger.error("while running: %s", cmd)
            logger.error("stdout: %s", stdout)
            logger.error("stderr: %s", stderr)


def make_guest_dirty_memory(ssh_connection, amount_mib=32):
    """Tell the guest, over ssh, to dirty `amount` pages of memory."""
    lower_ssh_oom_chance(ssh_connection)

    try:
        _ = ssh_connection.run(f"/usr/local/bin/fillmem {amount_mib}", timeout=1.0)
    except TimeoutExpired:
        # It's ok if this expires. Sometimes the SSH connection
        # gets killed by the OOM killer *after* the fillmem program
        # started. As a result, we can ignore timeouts here.
        pass

    time.sleep(5)


def _test_rss_memory_lower(test_microvm):
    """Check inflating the balloon makes guest use less rss memory."""
    # Get the firecracker pid, and open an ssh connection.
    ssh_connection = test_microvm.ssh

    # Using deflate_on_oom, get the RSS as low as possible
    test_microvm.api.balloon.patch(amount_mib=200)

    # Get initial rss consumption.
    init_rss = get_stable_rss_mem(test_microvm)

    # Get the balloon back to 0.
    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Dirty memory, then inflate balloon and get ballooned rss consumption.
    make_guest_dirty_memory(ssh_connection, amount_mib=32)

    test_microvm.api.balloon.patch(amount_mib=200)
    balloon_rss = get_stable_rss_mem(test_microvm)

    # Check that the ballooning reclaimed the memory.
    assert balloon_rss - init_rss <= 15000


# pylint: disable=C0103
def test_rss_memory_lower(uvm_plain_any):
    """
    Test that inflating the balloon makes guest use less rss memory.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )

    # Start the microvm.
    test_microvm.start()

    _test_rss_memory_lower(test_microvm)


# pylint: disable=C0103
def test_inflate_reduces_free(uvm_plain_any):
    """
    Check that the output of free in guest changes with inflate.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Install deflated balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1
    )

    # Start the microvm
    test_microvm.start()
    meminfo = MeminfoGuest(test_microvm)

    # Get the free memory before ballooning.
    available_mem_deflated = meminfo.get().mem_free.kib()

    # Inflate 64 MB == 16384 page balloon.
    test_microvm.api.balloon.patch(amount_mib=64)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Get the free memory after ballooning.
    available_mem_inflated = meminfo.get().mem_free.kib()

    # Assert that ballooning reclaimed about 64 MB of memory.
    assert available_mem_inflated <= available_mem_deflated - 85 * 64000 / 100


# pylint: disable=C0103
@pytest.mark.parametrize("deflate_on_oom", [True, False])
def test_deflate_on_oom(uvm_plain_any, deflate_on_oom):
    """
    Verify that setting the `deflate_on_oom` option works correctly.

    https://github.com/firecracker-microvm/firecracker/blob/main/docs/ballooning.md

    deflate_on_oom=True

      should result in balloon_stats['actual_mib'] be reduced

    deflate_on_oom=False

      should result in balloon_stats['actual_mib'] remain the same
    """

    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a deflated memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=deflate_on_oom, stats_polling_interval_s=1
    )

    # Start the microvm.
    test_microvm.start()

    # We get an initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 50 MiB in order to make sure we
    # get a lower reading than the initial one.
    initial_rss = get_stable_rss_mem(test_microvm)
    inflate_size = 256 - (int(initial_rss / 1024) + 50)

    # Inflate the balloon
    test_microvm.api.balloon.patch(amount_mib=inflate_size)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Check that using memory leads to the balloon device automatically
    # deflate (or not).
    balloon_size_before = test_microvm.api.balloon_stats.get().json()["actual_mib"]
    make_guest_dirty_memory(test_microvm.ssh, 128)

    try:
        balloon_size_after = test_microvm.api.balloon_stats.get().json()["actual_mib"]
    except requests.exceptions.ConnectionError:
        assert (
            not deflate_on_oom
        ), "Guest died even though it should have deflated balloon to alleviate memory pressure"

        test_microvm.mark_killed()
    else:
        print(f"size before: {balloon_size_before} size after: {balloon_size_after}")
        if deflate_on_oom:
            assert balloon_size_after < balloon_size_before, "Balloon did not deflate"
        else:
            assert balloon_size_after >= balloon_size_before, "Balloon deflated"
            # Kill it here, letting the infrastructure know that the process might
            # be dead already.
            test_microvm.kill(might_be_dead=True)


# pylint: disable=C0103
def test_reinflate_balloon(uvm_plain_any):
    """
    Verify that repeatedly inflating and deflating the balloon works.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a deflated memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )

    # Start the microvm.
    test_microvm.start()

    # First inflate the balloon to free up the uncertain amount of memory
    # used by the kernel at boot and establish a baseline, then give back
    # the memory.
    test_microvm.api.balloon.patch(amount_mib=200)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Get the guest to dirty memory.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=32)
    first_reading = get_stable_rss_mem(test_microvm)

    # Now inflate the balloon.
    test_microvm.api.balloon.patch(amount_mib=200)
    second_reading = get_stable_rss_mem(test_microvm)

    # Now deflate the balloon.
    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Now have the guest dirty memory again.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=32)
    third_reading = get_stable_rss_mem(test_microvm)

    # Now inflate the balloon again.
    test_microvm.api.balloon.patch(amount_mib=200)
    fourth_reading = get_stable_rss_mem(test_microvm)

    # Check that the memory used is the same after regardless of the previous
    # inflate history of the balloon (with the third reading being allowed
    # to be smaller than the first, since memory allocated at booting up
    # is probably freed after the first inflation.
    assert (third_reading - first_reading) <= 20000
    assert abs(second_reading - fourth_reading) <= 20000


# pylint: disable=C0103
def test_size_reduction(uvm_plain_any):
    """
    Verify that ballooning reduces RSS usage on a newly booted guest.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )

    # Start the microvm.
    test_microvm.start()

    # Check memory usage.
    first_reading = get_stable_rss_mem(test_microvm)

    # Have the guest drop its caches.
    test_microvm.ssh.run("sync; echo 3 > /proc/sys/vm/drop_caches")
    time.sleep(5)

    # We take the initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 10 MiB in order to make sure we
    # get a lower reading than the initial one.
    inflate_size = 256 - int(first_reading / 1024) + 10

    # Now inflate the balloon.
    test_microvm.api.balloon.patch(amount_mib=inflate_size)

    # Check memory usage again.
    second_reading = get_stable_rss_mem(test_microvm)

    # There should be a reduction of at least 10MB.
    assert first_reading - second_reading >= 10000


# pylint: disable=C0103
def test_stats(uvm_plain_any):
    """
    Verify that balloon stats work as expected.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a memory balloon with stats enabled.
    test_microvm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=STATS_POLLING_INTERVAL_S,
    )

    # Start the microvm.
    test_microvm.start()

    # Give Firecracker enough time to poll the stats at least once post-boot
    time.sleep(STATS_POLLING_INTERVAL_S * 2)

    # Get an initial reading of the stats.
    initial_stats = test_microvm.api.balloon_stats.get().json()

    # Major faults happen when a page fault has to be satisfied from disk. They are not
    # triggered by our `make_guest_dirty_memory` workload, as it uses MAP_ANONYMOUS, which
    # only triggers minor faults. However, during the boot process, things are read from the
    # rootfs, so we should at least see a non-zero number of major faults.
    assert initial_stats["major_faults"] > 0

    # Dirty 10MB of pages.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=10)
    time.sleep(1)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Make sure that the stats catch the page faults.
    after_workload_stats = test_microvm.api.balloon_stats.get().json()
    assert initial_stats.get("minor_faults", 0) < after_workload_stats["minor_faults"]

    # Now inflate the balloon with 10MB of pages.
    test_microvm.api.balloon.patch(amount_mib=10)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Get another reading of the stats after the polling interval has passed.
    inflated_stats = test_microvm.api.balloon_stats.get().json()

    # Ensure the stats reflect inflating the balloon.
    assert after_workload_stats["free_memory"] > inflated_stats["free_memory"]
    assert after_workload_stats["available_memory"] > inflated_stats["available_memory"]

    # Deflate the balloon.check that the stats show the increase in
    # available memory.
    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Get another reading of the stats after the polling interval has passed.
    deflated_stats = test_microvm.api.balloon_stats.get().json()

    # Ensure the stats reflect deflating the balloon.
    assert inflated_stats["free_memory"] < deflated_stats["free_memory"]
    assert inflated_stats["available_memory"] < deflated_stats["available_memory"]


def test_stats_update(uvm_plain_any):
    """
    Verify that balloon stats update correctly.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a memory balloon with stats enabled.
    test_microvm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=STATS_POLLING_INTERVAL_S,
    )

    # Start the microvm.
    test_microvm.start()

    # Dirty 30MB of pages.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=30)

    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem(test_microvm)

    # Get an initial reading of the stats.
    initial_stats = test_microvm.api.balloon_stats.get().json()

    # Inflate the balloon to trigger a change in the stats.
    test_microvm.api.balloon.patch(amount_mib=10)

    # Wait out the polling interval, then get the updated stats.
    time.sleep(STATS_POLLING_INTERVAL_S * 2)
    next_stats = test_microvm.api.balloon_stats.get().json()
    assert initial_stats["available_memory"] != next_stats["available_memory"]

    # Inflate the balloon more to trigger a change in the stats.
    test_microvm.api.balloon.patch(amount_mib=30)
    time.sleep(1)

    # Change the polling interval.
    test_microvm.api.balloon_stats.patch(stats_polling_interval_s=60)

    # The polling interval change should update the stats.
    final_stats = test_microvm.api.balloon_stats.get().json()
    assert next_stats["available_memory"] != final_stats["available_memory"]


def test_balloon_snapshot(uvm_plain_any, microvm_factory):
    """
    Test that the balloon works after pause/resume.
    """
    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )
    vm.add_net_iface()

    # Add a memory balloon with stats enabled.
    vm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=STATS_POLLING_INTERVAL_S,
    )

    vm.start()

    # Dirty 60MB of pages.
    make_guest_dirty_memory(vm.ssh, amount_mib=60)
    time.sleep(1)

    # Check memory usage.
    first_reading = get_stable_rss_mem(vm)

    # Now inflate the balloon with 20MB of pages.
    vm.api.balloon.patch(amount_mib=20)

    # Check memory usage again.
    second_reading = get_stable_rss_mem(vm)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert first_reading > second_reading

    snapshot = vm.snapshot_full()
    microvm = microvm_factory.build_from_snapshot(snapshot)

    # Wait out the polling interval, then get the updated stats.
    time.sleep(STATS_POLLING_INTERVAL_S * 2)
    stats_after_snap = microvm.api.balloon_stats.get().json()

    # Check memory usage.
    third_reading = get_stable_rss_mem(microvm)

    # Dirty 60MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount_mib=60)

    # Check memory usage.
    fourth_reading = get_stable_rss_mem(microvm)

    assert fourth_reading > third_reading

    # Inflate the balloon with another 20MB of pages.
    microvm.api.balloon.patch(amount_mib=40)

    fifth_reading = get_stable_rss_mem(microvm)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert fourth_reading > fifth_reading

    # Get the stats after we take a snapshot and dirty some memory,
    # then reclaim it.
    # Ensure we gave enough time for the stats to update.
    time.sleep(STATS_POLLING_INTERVAL_S * 2)
    latest_stats = microvm.api.balloon_stats.get().json()

    # Ensure the stats are still working after restore and show
    # that the balloon inflated.
    assert stats_after_snap["available_memory"] > latest_stats["available_memory"]


def test_memory_scrub(uvm_plain_any):
    """
    Test that the memory is zeroed after deflate.
    """
    microvm = uvm_plain_any
    microvm.spawn()
    microvm.basic_config(vcpu_count=2, mem_size_mib=256)
    microvm.add_net_iface()

    # Add a memory balloon with stats enabled.
    microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
    )

    microvm.start()

    # Dirty 60MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount_mib=60)

    # Now inflate the balloon with 60MB of pages.
    microvm.api.balloon.patch(amount_mib=60)

    # Get the firecracker pid, and open an ssh connection.

    # Wait for the inflate to complete.
    _ = get_stable_rss_mem(microvm)

    # Deflate the balloon completely.
    microvm.api.balloon.patch(amount_mib=0)

    # Wait for the deflate to complete.
    _ = get_stable_rss_mem(microvm)

    microvm.ssh.check_output("/usr/local/bin/readmem {} {}".format(60, 1))
