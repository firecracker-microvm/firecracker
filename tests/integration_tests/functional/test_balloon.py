# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for guest-side operations on /balloon resources."""

import logging
import os
import subprocess
import time

from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.matrix import TestMatrix, TestContext
from framework.utils import get_free_mem_ssh

import host_tools.network as net_tools  # pylint: disable=import-error


MB_TO_PAGES = 256


def get_rss_mem_by_pid(pid):
    """Get the RSS memory that a guest uses, given the pid of the guest."""
    output = subprocess.check_output("pmap -X {}".format(pid), shell=True)
    return int(output.decode('utf-8').split('\n')[-2].split()[1], 10)


def make_guest_dirty_memory(ssh_connection, should_oom=False, amount=8192):
    """Tell the guest, over ssh, to dirty `amount` pages of memory."""
    amount_in_mbytes = amount / MB_TO_PAGES

    exit_code, _, _ = ssh_connection.execute_command(
        "/sbin/fillmem {}".format(amount_in_mbytes)
    )

    cmd = "cat /tmp/fillmem_output.txt"
    _, stdout, _ = ssh_connection.execute_command(cmd)
    if should_oom:
        assert exit_code == 0 and (
            "OOM Killer stopped the program with "
            "signal 9, exit code 0"
        ) in stdout.read()
    else:
        assert exit_code == 0 and (
            "Memory filling was "
            "successful"
        ) in stdout.read()


def build_test_matrix(network_config, bin_cloner_path, logger):
    """Build a test matrix using the kernel with the balloon driver."""
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 256 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_256mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels(
        keyword="vmlinux-4.14"
    ))
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger,
        'snapshot_type': SnapshotType.FULL,
        'seq_len': 5
    }

    # Create the test matrix.
    return TestMatrix(
        context=test_context,
        artifact_sets=[
            microvm_artifacts,
            kernel_artifacts,
            disk_artifacts
        ]
    )


def copy_fillmem_to_rootfs(rootfs_path):
    """Build and copy the 'memfill' program to the rootfs."""
    subprocess.check_call("gcc ./host_tools/fillmem.c -o fillmem", shell=True)
    subprocess.check_call("mkdir tmpfs", shell=True)
    subprocess.check_call("mount {} tmpfs".format(rootfs_path), shell=True)
    subprocess.check_call("cp fillmem tmpfs/sbin/fillmem", shell=True)
    subprocess.check_call("rm fillmem", shell=True)
    subprocess.check_call("umount tmpfs", shell=True)
    subprocess.check_call("rmdir tmpfs", shell=True)


# pylint: disable=C0103
def test_rss_memory_lower(test_microvm_with_ssh_and_balloon, network_config):
    """Check inflating the balloon makes guest use less rss memory."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Add a memory balloon.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Using deflate_on_oom, get the RSS as low as possible
    response = test_microvm.balloon.patch(amount_mb=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Get initial rss consumption.
    init_rss = get_rss_mem_by_pid(firecracker_pid)

    # Get the balloon back to 0.
    response = test_microvm.balloon.patch(amount_mb=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(2)

    # Dirty memory, then inflate balloon and get ballooned rss consumption.
    make_guest_dirty_memory(ssh_connection)

    response = test_microvm.balloon.patch(amount_mb=200)

    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)
    balloon_rss = get_rss_mem_by_pid(firecracker_pid)

    # Check that the ballooning reclaimed the memory.
    assert balloon_rss - init_rss <= 15000


# pylint: disable=C0103
def test_inflate_reduces_free(test_microvm_with_ssh_and_balloon,
                              network_config):
    """Check that the output of free in guest changes with inflate."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Install deflated balloon.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=False,
        must_tell_host=False,
        stats_polling_interval_s=1
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm
    test_microvm.start()

    # Get and open an ssh connection.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get the free memory before ballooning.
    available_mem_deflated = get_free_mem_ssh(ssh_connection)

    # Inflate 64 MB == 16384 page balloon.
    response = test_microvm.balloon.patch(amount_mb=64)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Get the free memory after ballooning.
    available_mem_inflated = get_free_mem_ssh(ssh_connection)

    # Assert that ballooning reclaimed about 64 MB of memory.
    assert available_mem_inflated <= available_mem_deflated - 85 * 64000 / 100


# pylint: disable=C0103
def test_deflate_on_oom_true(test_microvm_with_ssh_and_balloon,
                             network_config):
    """Verify that setting the `deflate_on_oom` to True works correctly."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Add a deflated memory balloon.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get an ssh connection to the microvm.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Inflate the balloon
    response = test_microvm.balloon.patch(amount_mb=172)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Check that using memory doesn't lead to an out of memory error.
    # Note that due to `test_deflate_on_oom_false`, we know that
    # if `deflate_on_oom` were set to False, then such an error
    # would have happened.
    make_guest_dirty_memory(ssh_connection)


# pylint: disable=C0103
def test_deflate_on_oom_false(test_microvm_with_ssh_and_balloon,
                              network_config):
    """Verify that setting the `deflate_on_oom` to False works correctly."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Add a memory balloon.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=False,
        must_tell_host=False,
        stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get an ssh connection to the microvm.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Inflate the balloon.
    response = test_microvm.balloon.patch(amount_mb=172)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Check that using memory does lead to an out of memory error.
    make_guest_dirty_memory(ssh_connection, should_oom=True)


# pylint: disable=C0103
def test_reinflate_balloon(test_microvm_with_ssh_and_balloon, network_config):
    """Verify that repeatedly inflating and deflating the baloon works."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Add a deflated memory balloon.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection, get the RSS.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get the guest to dirty memory.
    make_guest_dirty_memory(ssh_connection)
    first_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon.
    response = test_microvm.balloon.patch(amount_mb=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)
    second_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon again.
    response = test_microvm.balloon.patch(amount_mb=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(2)

    # Now have the guest dirty memory again.
    make_guest_dirty_memory(ssh_connection)
    third_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon again.
    response = test_microvm.balloon.patch(amount_mb=200)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)
    fourth_reading = get_rss_mem_by_pid(firecracker_pid)

    # Check that the memory used is the same after regardless of the previous
    # inflate history of the balloon (with the third reading being allowed
    # to be smaller than the first, since memory allocated at booting up
    # is probably freed after the first inflation.
    assert (third_reading - first_reading) <= 20000
    assert abs(second_reading - fourth_reading) <= 20000


# pylint: disable=C0103
def test_size_reduction(test_microvm_with_ssh_and_balloon, network_config):
    """Verify that ballooning reduces RSS usage on a newly booted guest."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Add a memory balloon.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=0
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Check memory usage.
    first_reading = get_rss_mem_by_pid(firecracker_pid)

    # Have the guest drop its caches.
    ssh_connection.execute_command('sync; echo 3 > /proc/sys/vm/drop_caches')
    time.sleep(5)

    # Now inflate the balloon.
    response = test_microvm.balloon.patch(amount_mb=40)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Check memory usage again.
    second_reading = get_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction of at least 10MB.
    assert first_reading - second_reading >= 10000


# pylint: disable=C0103
def test_stats(test_microvm_with_ssh_and_balloon, network_config):
    """Verify that balloon stats work as expected."""
    test_microvm = test_microvm_with_ssh_and_balloon
    test_microvm.spawn()
    test_microvm.basic_config()
    _tap, _, _ = test_microvm.ssh_network_config(network_config, '1')
    test_microvm.ssh_config['ssh_key_path'] = os.path.join(
        test_microvm.fsfiles,
        'debian.rootfs.id_rsa'
    )

    # Add a memory balloon with stats enabled.
    response = test_microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=1
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Open an ssh connection to the microvm.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get an initial reading of the stats.
    initial_stats = test_microvm.balloon.get_stats().json()

    # Dirty 10MB of pages.
    make_guest_dirty_memory(ssh_connection, amount=(10 * MB_TO_PAGES))
    time.sleep(1)

    # Make sure that the stats catch the page faults.
    after_workload_stats = test_microvm.balloon.get_stats().json()
    assert initial_stats['minor_faults'] < after_workload_stats['minor_faults']
    assert initial_stats['major_faults'] < after_workload_stats['major_faults']

    # Now inflate the balloon with 10MB of pages.
    response = test_microvm.balloon.patch(amount_mb=10)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(1)

    # Get another reading of the stats after the polling interval has passed.
    inflated_stats = test_microvm.balloon.get_stats().json()

    # Ensure the stats reflect inflating the balloon.
    assert (
        after_workload_stats['free_memory'] >
        inflated_stats['free_memory']
    )
    assert (
        after_workload_stats['available_memory'] >
        inflated_stats['available_memory']
    )

    # Deflate the balloon.check that the stats show the increase in
    # available memory.
    response = test_microvm.balloon.patch(amount_mb=0)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(1)

    # Get another reading of the stats after the polling interval has passed.
    deflated_stats = test_microvm.balloon.get_stats().json()

    # Ensure the stats reflect deflating the balloon.
    assert (
        inflated_stats['free_memory'] <
        deflated_stats['free_memory']
    )
    assert (
        inflated_stats['available_memory'] <
        deflated_stats['available_memory']
    )


def test_balloon_snapshot(
    network_config,
    bin_cloner_path
):
    """Test that the balloon works after pause/resume."""
    logger = logging.getLogger("snapshot_sequence")

    # Create the test matrix.
    test_matrix = build_test_matrix(network_config, bin_cloner_path, logger)

    test_matrix.run_test(_test_balloon_snapshot)


def _test_balloon_snapshot(context):
    logger = context.custom['logger']
    vm_builder = context.custom['builder']
    snapshot_type = context.custom['snapshot_type']
    enable_diff_snapshots = snapshot_type == SnapshotType.DIFF

    logger.info("Testing {} with microvm: \"{}\", kernel {}, disk {} "
                .format(snapshot_type,
                        context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    # Create a rw copy artifact.
    root_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    basevm = vm_builder.build(kernel=context.kernel,
                              disks=[root_disk],
                              ssh_key=ssh_key,
                              config=context.microvm,
                              enable_diff_snapshots=enable_diff_snapshots)

    copy_fillmem_to_rootfs(root_disk.local_path())

    # Add a memory balloon with stats enabled.
    response = basevm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=1
    )
    assert basevm.api_session.is_status_no_content(response.status_code)

    basevm.start()
    ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

    # Dirty 60MB of pages.
    make_guest_dirty_memory(ssh_connection, amount=(60 * MB_TO_PAGES))
    time.sleep(1)

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = basevm.jailer_clone_pid

    # Check memory usage.
    first_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon with 20MB of pages.
    response = basevm.balloon.patch(amount_mb=20)
    assert basevm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Check memory usage again.
    second_reading = get_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert first_reading > second_reading

    logger.info("Create {} #0.".format(snapshot_type))
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    # Create base snapshot.
    snapshot = snapshot_builder.create([root_disk.local_path()],
                                       ssh_key,
                                       snapshot_type)

    basevm.kill()

    logger.info("Load snapshot #{}, mem {}".format(1, snapshot.mem))
    microvm, _ = vm_builder.build_from_snapshot(snapshot,
                                                True,
                                                enable_diff_snapshots)

    # Attempt to connect to resumed microvm.
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Get the firecracker from snapshot pid, and open an ssh connection.
    firecracker_pid = microvm.jailer_clone_pid

    # Check memory usage.
    third_reading = get_rss_mem_by_pid(firecracker_pid)

    # Dirty 60MB of pages.
    make_guest_dirty_memory(ssh_connection, amount=(60 * MB_TO_PAGES))
    time.sleep(1)

    # Check memory usage.
    fourth_reading = get_rss_mem_by_pid(firecracker_pid)

    assert fourth_reading > third_reading

    # Inflate the balloon with another 20MB of pages.
    response = microvm.balloon.patch(amount_mb=40)
    assert microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    fifth_reading = get_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction in RSS, but it's inconsistent.
    # We only test that the reduction happens.
    assert fourth_reading > fifth_reading

    microvm.kill()


def test_snapshot_compatibility(
    network_config,
    bin_cloner_path
):
    """Test that the balloon serializes correctly."""
    logger = logging.getLogger("snapshot_sequence")

    # Create the test matrix.
    test_matrix = build_test_matrix(network_config, bin_cloner_path, logger)

    test_matrix.run_test(_test_snapshot_compatibility)


def _test_snapshot_compatibility(context):
    logger = context.custom['logger']
    vm_builder = context.custom['builder']
    snapshot_type = context.custom['snapshot_type']
    enable_diff_snapshots = snapshot_type == SnapshotType.DIFF

    logger.info("Testing {} with microvm: \"{}\", kernel {}, disk {} "
                .format(snapshot_type,
                        context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))

    # Create a rw copy artifact.
    root_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from aftifacts.
    microvm = vm_builder.build(
        kernel=context.kernel,
        disks=[root_disk],
        ssh_key=ssh_key,
        config=context.microvm,
        enable_diff_snapshots=enable_diff_snapshots
    )

    # Add a memory balloon with stats enabled.
    response = microvm.balloon.put(
        amount_mb=0,
        deflate_on_oom=True,
        must_tell_host=False,
        stats_polling_interval_s=1
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()

    logger.info("Create {} #0.".format(snapshot_type))

    # Pause the microVM in order to allow snapshots
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Try to create a snapshot with a balloon on version 0.23.0.
    response = microvm.snapshot_create.put(
        mem_file_path='memfile',
        snapshot_path='dummy',
        diff=False,
        version='0.23.0'
    )

    # This should fail as the balloon was introduced in 0.24.0.
    assert microvm.api_session.is_status_bad_request(response.status_code)
    assert (
        'Target version does not implement the '
        'virtio-balloon device'
    ) in response.json()['fault_message']

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(microvm)

    # Check we can create a snapshot with a balloon on current version.
    snapshot_builder.create(
        [root_disk.local_path()],
        ssh_key,
        snapshot_type
    )

    microvm.kill()
