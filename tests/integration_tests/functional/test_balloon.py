# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /balloon resources."""

import logging
import time

from retry import retry

from framework.artifacts import NetIfaceConfig
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.utils import get_free_mem_ssh, run_cmd

MB_TO_PAGES = 256
STATS_POLLING_INTERVAL_S = 1


@retry(delay=0.5, tries=10)
def get_stable_rss_mem_by_pid(pid, percentage_delta=0.5):
    """
    Get the RSS memory that a guest uses, given the pid of the guest.

    Wait till the fluctuations in RSS drop below percentage_delta. If timeout
    is reached before the fluctuations drop, raise an exception.
    """

    def get_rss_from_pmap():
        _, output, _ = run_cmd("pmap -X {}".format(pid))
        return int(output.split("\n")[-2].split()[1], 10)

    first_rss = get_rss_from_pmap()
    time.sleep(1)
    second_rss = get_rss_from_pmap()

    delta = (abs(first_rss - second_rss) / float(first_rss)) * 100
    assert delta < percentage_delta

    return second_rss


def make_guest_dirty_memory(ssh_connection, should_oom=False, amount=8192):
    """Tell the guest, over ssh, to dirty `amount` pages of memory."""
    logger = logging.getLogger("make_guest_dirty_memory")

    amount_in_mbytes = amount / MB_TO_PAGES

    cmd = f"/sbin/fillmem {amount_in_mbytes}"
    exit_code, stdout, stderr = ssh_connection.execute_command(cmd)
    # add something to the logs for troubleshooting
    if exit_code != 0:
        logger.error("while running: %s", cmd)
        logger.error("stdout: %s", stdout.read())
        logger.error("stderr: %s", stderr.read())

    cmd = "cat /tmp/fillmem_output.txt"
    _, stdout, _ = ssh_connection.execute_command(cmd)
    if should_oom:
        assert (
            "OOM Killer stopped the program with "
            "signal 9, exit code 0" in stdout.read()
        )
    else:
        assert exit_code == 0, stderr.read()
        stdout_txt = stdout.read()
        assert "Memory filling was successful" in stdout_txt, stdout_txt


def _test_rss_memory_lower(test_microvm):
    """Check inflating the balloon makes guest use less rss memory."""
    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # Using deflate_on_oom, get the RSS as low as possible
    response = test_microvm.balloon.patch(amount_mib=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Get initial rss consumption.
    init_rss = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get the balloon back to 0.
    response = test_microvm.balloon.patch(amount_mib=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Dirty memory, then inflate balloon and get ballooned rss consumption.
    make_guest_dirty_memory(ssh_connection)

    response = test_microvm.balloon.patch(amount_mib=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    balloon_rss = get_stable_rss_mem_by_pid(firecracker_pid)

    # Check that the ballooning reclaimed the memory.
    assert balloon_rss - init_rss <= 15000


# pylint: disable=C0103
def test_rss_memory_lower(test_microvm_with_api, network_config):
    """
    Test that inflating the balloon makes guest use less rss memory.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a memory balloon.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    _test_rss_memory_lower(test_microvm)


# pylint: disable=C0103
def test_inflate_reduces_free(test_microvm_with_api, network_config):
    """
    Check that the output of free in guest changes with inflate.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Install deflated balloon.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=1
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm
    test_microvm.start()

    # Get and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # Get the free memory before ballooning.
    available_mem_deflated = get_free_mem_ssh(ssh_connection)

    # Inflate 64 MB == 16384 page balloon.
    response = test_microvm.balloon.patch(amount_mib=64)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get the free memory after ballooning.
    available_mem_inflated = get_free_mem_ssh(ssh_connection)

    # Assert that ballooning reclaimed about 64 MB of memory.
    assert available_mem_inflated <= available_mem_deflated - 85 * 64000 / 100


# pylint: disable=C0103
def test_deflate_on_oom_true(test_microvm_with_api, network_config):
    """
    Verify that setting the `deflate_on_oom` to True works correctly.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a deflated memory balloon.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get an ssh connection to the microvm.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # We get an initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 10 MiB in order to make sure we
    # get a lower reading than the initial one.
    initial_rss = get_stable_rss_mem_by_pid(firecracker_pid)
    inflate_size = 256 - int(initial_rss / 1024) + 10

    # Inflate the balloon
    response = test_microvm.balloon.patch(amount_mib=inflate_size)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Check that using memory doesn't lead to an out of memory error.
    # Note that due to `test_deflate_on_oom_false`, we know that
    # if `deflate_on_oom` were set to False, then such an error
    # would have happened.
    make_guest_dirty_memory(ssh_connection)


# pylint: disable=C0103
def test_deflate_on_oom_false(test_microvm_with_api, network_config):
    """
    Verify that setting the `deflate_on_oom` to False works correctly.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a memory balloon.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get an ssh connection to the microvm.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # We get an initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 10 MiB in order to make sure we
    # get a lower reading than the initial one.
    initial_rss = get_stable_rss_mem_by_pid(firecracker_pid)
    inflate_size = 256 - int(initial_rss / 1024) + 10

    # Inflate the balloon.
    response = test_microvm.balloon.patch(amount_mib=inflate_size)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Check that using memory does lead to an out of memory error.
    make_guest_dirty_memory(ssh_connection, should_oom=True)


# pylint: disable=C0103
def test_reinflate_balloon(test_microvm_with_api, network_config):
    """
    Verify that repeatedly inflating and deflating the balloon works.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a deflated memory balloon.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection, get the RSS.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # First inflate the balloon to free up the uncertain amount of memory
    # used by the kernel at boot and establish a baseline, then give back
    # the memory.
    response = test_microvm.balloon.patch(amount_mib=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    response = test_microvm.balloon.patch(amount_mib=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get the guest to dirty memory.
    make_guest_dirty_memory(ssh_connection)
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon.
    response = test_microvm.balloon.patch(amount_mib=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now deflate the balloon.
    response = test_microvm.balloon.patch(amount_mib=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now have the guest dirty memory again.
    make_guest_dirty_memory(ssh_connection)
    third_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon again.
    response = test_microvm.balloon.patch(amount_mib=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    fourth_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Check that the memory used is the same after regardless of the previous
    # inflate history of the balloon (with the third reading being allowed
    # to be smaller than the first, since memory allocated at booting up
    # is probably freed after the first inflation.
    assert (third_reading - first_reading) <= 20000
    assert abs(second_reading - fourth_reading) <= 20000


# pylint: disable=C0103
def test_size_reduction(test_microvm_with_api, network_config):
    """
    Verify that ballooning reduces RSS usage on a newly booted guest.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a memory balloon.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # Check memory usage.
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Have the guest drop its caches.
    ssh_connection.execute_command("sync; echo 3 > /proc/sys/vm/drop_caches")
    time.sleep(5)

    # We take the initial reading of the RSS, then calculate the amount
    # we need to inflate the balloon with by subtracting it from the
    # VM size and adding an offset of 10 MiB in order to make sure we
    # get a lower reading than the initial one.
    inflate_size = 256 - int(first_reading / 1024) + 10

    # Now inflate the balloon.
    response = test_microvm.balloon.patch(amount_mib=inflate_size)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Check memory usage again.
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction of at least 10MB.
    assert first_reading - second_reading >= 10000


# pylint: disable=C0103
def test_stats(test_microvm_with_api, network_config):
    """
    Verify that balloon stats work as expected.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a memory balloon with stats enabled.
    response = test_microvm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Open an ssh connection to the microvm.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # Get an initial reading of the stats.
    initial_stats = test_microvm.balloon.get_stats().json()

    # Dirty 10MB of pages.
    make_guest_dirty_memory(ssh_connection, amount=10 * MB_TO_PAGES)
    time.sleep(1)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Make sure that the stats catch the page faults.
    after_workload_stats = test_microvm.balloon.get_stats().json()
    assert initial_stats["minor_faults"] < after_workload_stats["minor_faults"]
    assert initial_stats["major_faults"] < after_workload_stats["major_faults"]

    # Now inflate the balloon with 10MB of pages.
    response = test_microvm.balloon.patch(amount_mib=10)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get another reading of the stats after the polling interval has passed.
    inflated_stats = test_microvm.balloon.get_stats().json()

    # Ensure the stats reflect inflating the balloon.
    assert after_workload_stats["free_memory"] > inflated_stats["free_memory"]
    assert after_workload_stats["available_memory"] > inflated_stats["available_memory"]

    # Deflate the balloon.check that the stats show the increase in
    # available memory.
    response = test_microvm.balloon.patch(amount_mib=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get another reading of the stats after the polling interval has passed.
    deflated_stats = test_microvm.balloon.get_stats().json()

    # Ensure the stats reflect deflating the balloon.
    assert inflated_stats["free_memory"] < deflated_stats["free_memory"]
    assert inflated_stats["available_memory"] < deflated_stats["available_memory"]


def test_stats_update(test_microvm_with_api, network_config):
    """
    Verify that balloon stats update correctly.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, "1")

    # Add a memory balloon with stats enabled.
    response = test_microvm.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=STATS_POLLING_INTERVAL_S,
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Open an ssh connection to the microvm.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = test_microvm.ssh

    # Dirty 30MB of pages.
    make_guest_dirty_memory(ssh_connection, amount=30 * MB_TO_PAGES)

    # This call will internally wait for rss to become stable.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Get an initial reading of the stats.
    initial_stats = test_microvm.balloon.get_stats().json()

    # Inflate the balloon to trigger a change in the stats.
    response = test_microvm.balloon.patch(amount_mib=10)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Wait out the polling interval, then get the updated stats.
    time.sleep(STATS_POLLING_INTERVAL_S)
    next_stats = test_microvm.balloon.get_stats().json()
    assert initial_stats["available_memory"] != next_stats["available_memory"]

    # Inflate the balloon more to trigger a change in the stats.
    response = test_microvm.balloon.patch(amount_mib=30)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Change the polling interval.
    response = test_microvm.balloon.patch_stats(stats_polling_interval_s=60)
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # The polling interval change should update the stats.
    final_stats = test_microvm.balloon.get_stats().json()
    assert next_stats["available_memory"] != final_stats["available_memory"]


def test_balloon_snapshot(bin_cloner_path, microvm_factory, guest_kernel, rootfs):
    """
    Test that the balloon works after pause/resume.
    """
    logger = logging.getLogger("snapshot_sequence")
    snapshot_type = SnapshotType.FULL
    diff_snapshots = snapshot_type == SnapshotType.DIFF

    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
        track_dirty_pages=diff_snapshots,
    )
    iface = NetIfaceConfig()
    vm.add_net_iface(iface)

    # Add a memory balloon with stats enabled.
    response = vm.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=STATS_POLLING_INTERVAL_S,
    )
    assert vm.api_session.is_status_no_content(response.status_code)

    vm.start()

    # Dirty 60MB of pages.
    make_guest_dirty_memory(vm.ssh, amount=60 * MB_TO_PAGES)
    time.sleep(1)

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = vm.jailer_clone_pid

    # Check memory usage.
    first_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon with 20MB of pages.
    response = vm.balloon.patch(amount_mib=20)
    assert vm.api_session.is_status_no_content(response.status_code)

    # Check memory usage again.
    second_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert first_reading > second_reading

    logger.info("Create %s #0.", snapshot_type)
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)
    disks = [vm.rootfs_file]
    # Create base snapshot.
    snapshot = snapshot_builder.create(
        disks, rootfs.ssh_key(), snapshot_type, net_ifaces=[iface]
    )
    vm.kill()

    logger.info("Load snapshot #%d, mem %s", 1, snapshot.mem)
    vm_builder = MicrovmBuilder(bin_cloner_path)
    microvm, _ = vm_builder.build_from_snapshot(
        snapshot, resume=True, diff_snapshots=diff_snapshots
    )
    # Attempt to connect to resumed microvm.
    microvm.ssh.run("true")

    # Get the firecracker from snapshot pid, and open an ssh connection.
    firecracker_pid = microvm.jailer_clone_pid

    # Wait out the polling interval, then get the updated stats.
    time.sleep(STATS_POLLING_INTERVAL_S)
    stats_after_snap = microvm.balloon.get_stats().json()

    # Check memory usage.
    third_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # Dirty 60MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount=60 * MB_TO_PAGES)

    # Check memory usage.
    fourth_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    assert fourth_reading > third_reading

    # Inflate the balloon with another 20MB of pages.
    response = microvm.balloon.patch(amount_mib=40)
    assert microvm.api_session.is_status_no_content(response.status_code)

    fifth_reading = get_stable_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert fourth_reading > fifth_reading

    # Get the stats after we take a snapshot and dirty some memory,
    # then reclaim it.
    latest_stats = microvm.balloon.get_stats().json()

    # Ensure the stats are still working after restore and show
    # that the balloon inflated.
    assert stats_after_snap["available_memory"] > latest_stats["available_memory"]


def test_snapshot_compatibility(microvm_factory, guest_kernel, rootfs):
    """
    Test that the balloon serializes correctly.
    """
    logger = logging.getLogger("snapshot_compatibility")
    snapshot_type = SnapshotType.FULL
    diff_snapshots = snapshot_type == SnapshotType.DIFF

    vm = microvm_factory.build(guest_kernel, rootfs)
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=256,
        track_dirty_pages=diff_snapshots,
    )

    # Add a memory balloon with stats enabled.
    response = vm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
    )
    assert vm.api_session.is_status_no_content(response.status_code)

    vm.start()

    logger.info("Create %s #0.", snapshot_type)

    # Pause the microVM in order to allow snapshots
    response = vm.vm.patch(state="Paused")
    assert vm.api_session.is_status_no_content(response.status_code)

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)

    # Check we can create a snapshot with a balloon on current version.
    snapshot_builder.create([rootfs.local_path()], rootfs.ssh_key(), snapshot_type)


def test_memory_scrub(microvm_factory, guest_kernel, rootfs, network_config):
    """
    Test that the memory is zeroed after deflate.
    """
    microvm = microvm_factory.build(guest_kernel, rootfs)
    microvm.spawn()
    microvm.basic_config(vcpu_count=2, mem_size_mib=256)
    microvm.ssh_network_config(network_config, "1")

    # Add a memory balloon with stats enabled.
    response = microvm.balloon.put(
        amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()

    # Dirty 60MB of pages.
    make_guest_dirty_memory(microvm.ssh, amount=60 * MB_TO_PAGES)

    # Now inflate the balloon with 60MB of pages.
    response = microvm.balloon.patch(amount_mib=60)
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = microvm.jailer_clone_pid

    # Wait for the inflate to complete.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    # Deflate the balloon completely.
    response = microvm.balloon.patch(amount_mib=0)
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Wait for the deflate to complete.
    _ = get_stable_rss_mem_by_pid(firecracker_pid)

    exit_code, _, _ = microvm.ssh.execute_command("/sbin/readmem {} {}".format(60, 1))
    assert exit_code == 0
