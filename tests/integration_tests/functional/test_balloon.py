# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /balloon resources."""

import logging
import time

import pytest
from retry import retry

from framework.utils import get_free_mem_ssh, run_cmd

STATS_POLLING_INTERVAL_S = 1


@retry(delay=0.5, tries=10, logger=None)
def get_stable_rss_mem_by_pid(pid, percentage_delta=1):
    """
    Get the RSS memory that a guest uses, given the pid of the guest.

    Wait till the fluctuations in RSS drop below percentage_delta. If timeout
    is reached before the fluctuations drop, raise an exception.
    """

    # All values are reported as KiB

    def get_rss_from_pmap():
        _, output, _ = run_cmd("pmap -X {}".format(pid))
        return int(output.split("\n")[-2].split()[1], 10)

    first_rss = get_rss_from_pmap()
    time.sleep(1)
    second_rss = get_rss_from_pmap()
    print(f"RSS readings: {first_rss}, {second_rss}")
    abs_diff = abs(first_rss - second_rss)
    abs_delta = 100 * abs_diff / first_rss
    assert abs_delta < percentage_delta or abs_diff < 2**10
    return second_rss


def lower_ssh_oom_chance(ssh_connection):
    """Lure OOM away from ssh process"""
    logger = logging.getLogger("lower_ssh_oom_chance")

    cmd = "pidof sshd"
    exit_code, stdout, stderr = ssh_connection.run(cmd)
    # add something to the logs for troubleshooting
    if exit_code != 0:
        logger.error("while running: %s", cmd)
        logger.error("stdout: %s", stdout)
        logger.error("stderr: %s", stderr)

    for pid in stdout.split(" "):
        cmd = f"choom -n -1000 -p {pid}"
        ssh_connection.run(cmd)


def make_guest_dirty_memory(ssh_connection, should_oom=False, amount_mib=32):
    """Tell the guest, over ssh, to dirty `amount` pages of memory."""
    logger = logging.getLogger("make_guest_dirty_memory")

    lower_ssh_oom_chance(ssh_connection)

    # Aim OOM at fillmem process
    cmd = f"choom -n 1000 -- /usr/local/bin/fillmem {amount_mib}"
    exit_code, stdout, stderr = ssh_connection.run(cmd)
    # add something to the logs for troubleshooting
    if exit_code != 0:
        logger.error("while running: %s", cmd)
        logger.error("stdout: %s", stdout)
        logger.error("stderr: %s", stderr)

    cmd = "cat /tmp/fillmem_output.txt"
    tries = 3
    while tries > 0:
        # it may take a bit of time to dirty the memory and the OOM to kick-in
        time.sleep(0.5)
        _, stdout, _ = ssh_connection.run(cmd)
        if stdout != "":
            break
        tries -= 1

    if should_oom:
        assert "OOM Killer stopped the program with signal 9, exit code 0" in stdout
    else:
        assert exit_code == 0, stderr
        assert "Memory filling was successful" in stdout, stdout


def _test_rss_memory_lower(test_microvm, stable_delta=1):
    """Check inflating the balloon makes guest use less rss memory."""
    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # Using deflate_on_oom, get the RSS as low as possible
    test_microvm.api.balloon.patch(amount_mib=200)

    # Get initial rss consumption.
    init_rss = get_stable_rss_mem_by_pid(firecracker_pid, percentage_delta=stable_delta)

    # Get the balloon back to 0.
    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid, percentage_delta=stable_delta)

    # Dirty memory, then inflate balloon and get ballooned rss consumption.
    make_guest_dirty_memory(ssh_connection, amount_mib=32)

    test_microvm.api.balloon.patch(amount_mib=200)
    balloon_rss = get_stable_rss_mem_by_pid(
        firecracker_pid, percentage_delta=stable_delta
    )

    # Check that the ballooning reclaimed the memory.
    assert balloon_rss - init_rss <= 15000


# pylint: disable=C0103
def test_rss_memory_lower(test_microvm_with_api):
    """
    Test that inflating the balloon makes guest use less rss memory.
    """
    test_microvm = test_microvm_with_api
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
def test_inflate_reduces_free(test_microvm_with_api):
    """
    Check that the output of free in guest changes with inflate.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Install deflated balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1
    )

    # Start the microvm
    test_microvm.start()
    firecracker_pid = test_microvm.jailer_clone_pid

    # Get the free memory before ballooning.
    available_mem_deflated = get_free_mem_ssh(test_microvm.ssh)

    # Inflate 64 MB == 16384 page balloon.
    test_microvm.api.balloon.patch(amount_mib=64)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get the free memory after ballooning.
    available_mem_inflated = get_free_mem_ssh(test_microvm.ssh)

    # Assert that ballooning reclaimed about 64 MB of memory.
    assert available_mem_inflated <= available_mem_deflated - 85 * 64000 / 100


# pylint: disable=C0103
@pytest.mark.parametrize("deflate_on_oom", [True, False])
def test_deflate_on_oom(test_microvm_with_api, deflate_on_oom):
    """
    Verify that setting the `deflate_on_oom` option works correctly.

    https://github.com/firecracker-microvm/firecracker/blob/main/docs/ballooning.md

    deflate_on_oom=True

      should not result in an OOM kill

    deflate_on_oom=False

      should result in an OOM kill
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a deflated memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=deflate_on_oom, stats_polling_interval_s=0
    )

    # Start the microvm.
    test_microvm.start()
    firecracker_pid = test_microvm.jailer_clone_pid

    # We get an initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 10 MiB in order to make sure we
    # get a lower reading than the initial one.
    initial_rss = get_stable_rss_mem_by_pid(firecracker_pid)
    inflate_size = 256 - int(initial_rss / 1024) + 10

    # Inflate the balloon
    test_microvm.api.balloon.patch(amount_mib=inflate_size)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Check that using memory leads an out of memory error (or not).
    make_guest_dirty_memory(test_microvm.ssh, should_oom=not deflate_on_oom)


# pylint: disable=C0103
def test_reinflate_balloon(test_microvm_with_api):
    """
    Verify that repeatedly inflating and deflating the balloon works.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a deflated memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )

    # Start the microvm.
    test_microvm.start()
    firecracker_pid = test_microvm.jailer_clone_pid

    # First inflate the balloon to free up the uncertain amount of memory
    # used by the kernel at boot and establish a baseline, then give back
    # the memory.
    # wait until boot completes:
    test_microvm.ssh.run("true")
    test_microvm.api.balloon.patch(amount_mib=200)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get the guest to dirty memory.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=32)
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon.
    test_microvm.api.balloon.patch(amount_mib=200)
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now deflate the balloon.
    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now have the guest dirty memory again.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=32)
    third_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon again.
    test_microvm.api.balloon.patch(amount_mib=200)
    fourth_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Check that the memory used is the same after regardless of the previous
    # inflate history of the balloon (with the third reading being allowed
    # to be smaller than the first, since memory allocated at booting up
    # is probably freed after the first inflation.
    assert (third_reading - first_reading) <= 20000
    assert abs(second_reading - fourth_reading) <= 20000


# pylint: disable=C0103
def test_size_reduction(test_microvm_with_api):
    """
    Verify that ballooning reduces RSS usage on a newly booted guest.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a memory balloon.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )

    # Start the microvm.
    test_microvm.start()
    firecracker_pid = test_microvm.jailer_clone_pid

    # Check memory usage.
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)

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
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction of at least 10MB.
    assert first_reading - second_reading >= 10000


# pylint: disable=C0103
def test_stats(test_microvm_with_api):
    """
    Verify that balloon stats work as expected.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a memory balloon with stats enabled.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
    )

    # Start the microvm.
    test_microvm.start()
    firecracker_pid = test_microvm.jailer_clone_pid

    # Get an initial reading of the stats.
    initial_stats = test_microvm.api.balloon_stats.get().json()

    # Dirty 10MB of pages.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=10)
    time.sleep(1)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Make sure that the stats catch the page faults.
    after_workload_stats = test_microvm.api.balloon_stats.get().json()
    assert initial_stats.get("minor_faults", 0) < after_workload_stats["minor_faults"]
    assert initial_stats.get("major_faults", 0) < after_workload_stats["major_faults"]

    # Now inflate the balloon with 10MB of pages.
    test_microvm.api.balloon.patch(amount_mib=10)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get another reading of the stats after the polling interval has passed.
    inflated_stats = test_microvm.api.balloon_stats.get().json()

    # Ensure the stats reflect inflating the balloon.
    assert after_workload_stats["free_memory"] > inflated_stats["free_memory"]
    assert after_workload_stats["available_memory"] > inflated_stats["available_memory"]

    # Deflate the balloon.check that the stats show the increase in
    # available memory.
    test_microvm.api.balloon.patch(amount_mib=0)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get another reading of the stats after the polling interval has passed.
    deflated_stats = test_microvm.api.balloon_stats.get().json()

    # Ensure the stats reflect deflating the balloon.
    assert inflated_stats["free_memory"] < deflated_stats["free_memory"]
    assert inflated_stats["available_memory"] < deflated_stats["available_memory"]


def test_stats_update(test_microvm_with_api):
    """
    Verify that balloon stats update correctly.
    """
    test_microvm = test_microvm_with_api
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
    firecracker_pid = test_microvm.jailer_clone_pid

    # Dirty 30MB of pages.
    make_guest_dirty_memory(test_microvm.ssh, amount_mib=30)

    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get an initial reading of the stats.
    initial_stats = test_microvm.api.balloon_stats.get().json()

    # Inflate the balloon to trigger a change in the stats.
    test_microvm.api.balloon.patch(amount_mib=10)

    # Wait out the polling interval, then get the updated stats.
    time.sleep(STATS_POLLING_INTERVAL_S)
    next_stats = test_microvm.api.balloon_stats.get().json()
    assert initial_stats["available_memory"] != next_stats["available_memory"]

    # Inflate the balloon more to trigger a change in the stats.
    test_microvm.api.balloon.patch(amount_mib=30)

    # Change the polling interval.
    test_microvm.api.balloon_stats.patch(stats_polling_interval_s=60)

    # The polling interval change should update the stats.
    final_stats = test_microvm.api.balloon_stats.get().json()
    assert next_stats["available_memory"] != final_stats["available_memory"]


def test_balloon_snapshot(microvm_factory, guest_kernel, rootfs):
    """
    Test that the balloon works after pause/resume.
    """
    vm = microvm_factory.build(guest_kernel, rootfs)
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

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = vm.jailer_clone_pid

    # Check memory usage.
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon with 20MB of pages.
    vm.api.balloon.patch(amount_mib=20)

    # Check memory usage again.
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert first_reading > second_reading

    snapshot = vm.snapshot_full()
    microvm = microvm_factory.build()
    microvm.spawn()
    microvm.restore_from_snapshot(snapshot)
    microvm.resume()

    # Attempt to connect to resumed microvm.
    microvm.ssh.run("true")

    # Get the firecracker from snapshot pid, and open an ssh connection.
    firecracker_pid = microvm.jailer_clone_pid

    # Wait out the polling interval, then get the updated stats.
    time.sleep(STATS_POLLING_INTERVAL_S)
    stats_after_snap = microvm.api.balloon_stats.get().json()

    # Check memory usage.
    third_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Dirty 60MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount_mib=60)

    # Check memory usage.
    fourth_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    assert fourth_reading > third_reading

    # Inflate the balloon with another 20MB of pages.
    microvm.api.balloon.patch(amount_mib=40)

    fifth_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert fourth_reading > fifth_reading

    # Get the stats after we take a snapshot and dirty some memory,
    # then reclaim it.
    latest_stats = microvm.api.balloon_stats.get().json()

    # Ensure the stats are still working after restore and show
    # that the balloon inflated.
    assert stats_after_snap["available_memory"] > latest_stats["available_memory"]


def test_snapshot_compatibility(microvm_factory, guest_kernel, rootfs):
    """
    Test that the balloon serializes correctly.
    """
    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
    )

    # Add a memory balloon with stats enabled.
    vm.api.balloon.put(amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1)

    vm.start()
    vm.snapshot_full()


def test_memory_scrub(microvm_factory, guest_kernel, rootfs):
    """
    Test that the memory is zeroed after deflate.
    """
    microvm = microvm_factory.build(guest_kernel, rootfs)
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
    firecracker_pid = microvm.jailer_clone_pid

    # Wait for the inflate to complete.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Deflate the balloon completely.
    microvm.api.balloon.patch(amount_mib=0)

    # Wait for the deflate to complete.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    exit_code, _, _ = microvm.ssh.run("/usr/local/bin/readmem {} {}".format(60, 1))
    assert exit_code == 0
