# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for memory ballooning functionality."""

import platform
import time
import os
import subprocess
import pytest
import host_tools.network as net_tools  # pylint: disable=import-error


def get_free_mem_ssh(ssh_connection):
    """Get how much free memory a guest sees, over an ssh connection."""
    def _available_mem(free_output):
        for line in free_output.split('\n'):
            if line.startswith('Mem:'):
                # 'available' is the last column.
                return int(line.split()[-1])
        raise Exception('Available memory not found in `free` output')
    _, stdout, stderr = ssh_connection.execute_command('free')
    assert stderr.read().decode('utf-8') == ''
    return _available_mem(stdout.read().decode('utf-8'))


def get_rss_mem_by_pid(pid):
    """Get the RSS memory that a guest uses, given the pid of the guest."""
    output = subprocess.check_output("pmap -X {}".format(pid), shell=True)
    return int(output.decode('utf-8').split('\n')[-2].split()[1], 10)


def make_guest_dirty_memory(ssh_connection, should_oom=False, amount=8192):
    """Tell the guest, over ssh, to dirty `amount` pages of memory."""
    exit_code, _, _ = ssh_connection.execute_command(
        "dd if=/dev/urandom of=/dev/shm/fill count={} bs=4k".format(amount)
    )
    # TODO: Better way to detect guest oom.
    # At the moment, I check that the ssh connection was killed by the OOM
    # killer (i.e. the command exits with exit code 255).
    # I would prefer somehow stopping ssh from being killed, and checking that
    # the return code for the previous command is 137 (i.e. the exit code for
    # an oom killed process).
    assert ((should_oom and exit_code == 255)
            or (not should_oom and exit_code == 0))
    time.sleep(0.1)
    ssh_connection.execute_command(
        "cat /dev/shm/fill > /dev/null"
    )
    time.sleep(0.1)


# pylint: disable=C0103
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="The balloon device is less effectiv on arm64 architecture"
)
def test_rss_memory_lower(test_microvm_with_ssh_and_balloon, network_config):
    """Check inflating the balloon makes guess use less rss memory."""
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
        num_pages=0,
        deflate_on_oom=True,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get initial rss consumption.
    init_rss = get_rss_mem_by_pid(firecracker_pid)

    # Dirty memory, then inflate balloon and get ballooned rss consumption.
    make_guest_dirty_memory(ssh_connection)
    response = test_microvm.balloon.patch(num_pages=36000)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)
    balloon_rss = get_rss_mem_by_pid(firecracker_pid)

    # Check that the ballooning reclaimed the memory.
    assert balloon_rss - init_rss <= 10000


# pylint: disable=C0103
def test_inflate_reduces_free(test_microvm_with_ssh_and_balloon,
                              network_config):
    """Verify that inflating a balloon leaves the guest with less memory."""
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
        num_pages=0,
        deflate_on_oom=False,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm
    test_microvm.start()

    # Get and open an ssh connection.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get the free memory before ballooning.
    available_mem_deflated = get_free_mem_ssh(ssh_connection)

    # Inflate 64 MB == 16384 page balloon.
    response = test_microvm.balloon.patch(num_pages=16384)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Get the free memory after ballooning.
    available_mem_inflated = get_free_mem_ssh(ssh_connection)

    # Assert that ballooning reclaimed about 64 MB of memory.
    assert available_mem_inflated <= available_mem_deflated - 85 * 64000 / 100


# pylint: disable=C0103
def test_deflate_on_oom_true(test_microvm_with_ssh_and_balloon,
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

    # Add a deflated memory balloon.
    response = test_microvm.balloon.put(
        num_pages=0,
        deflate_on_oom=True,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get an ssh connection to the microvm.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Inflate the balloon
    response = test_microvm.balloon.patch(num_pages=44000)
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
        num_pages=0,
        deflate_on_oom=False,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get an ssh connection to the microvm.
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Inflate the balloon.
    response = test_microvm.balloon.patch(num_pages=44000)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Check that using memory does lead to an out of memory error.
    make_guest_dirty_memory(ssh_connection, should_oom=True)


# pylint: disable=C0103
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="The balloon device is less effectiv on arm64 architecture"
)
def test_reinflate_balloon(test_microvm_with_ssh_and_balloon, network_config):
    """Verify that repeatedly inflating and deinflatiing the baloon works."""
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
        num_pages=0,
        deflate_on_oom=True,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Get the guest to dirty memory.
    make_guest_dirty_memory(ssh_connection)
    first_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon.
    response = test_microvm.balloon.patch(num_pages=44000)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)
    second_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now have the guest dirty memory again.
    make_guest_dirty_memory(ssh_connection)
    third_reading = get_rss_mem_by_pid(firecracker_pid)

    # Now inflate the balloon again.
    response = test_microvm.balloon.patch(num_pages=44000)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)
    fourth_reading = get_rss_mem_by_pid(firecracker_pid)

    # Check that the memory used is the same after regardles of the previous
    # inflate history of the balloon (with the third reading being allowed
    # to be smaller than the first, since memory allocated at booting up
    # is probably freed after the first inflation.
    assert (third_reading - first_reading) <= 10000
    assert abs(second_reading - fourth_reading) <= 10000


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
        num_pages=0,
        deflate_on_oom=True,
        must_tell_host=False
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Start the microvm.
    test_microvm.start()

    # Get the firecracker pid, and open an ssh connection.
    firecracker_pid = test_microvm.jailer_clone_pid
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Check memory usage.
    first_reading = get_rss_mem_by_pid(firecracker_pid)

    # Have the guest drop it's caches.
    ssh_connection.execute_command('sync; echo 3 > /proc/sys/vm/drop_caches')
    time.sleep(5)

    # Now inflate the balloon.
    response = test_microvm.balloon.patch(num_pages=10000)
    assert test_microvm.api_session.is_status_no_content(response.status_code)
    time.sleep(5)

    # Check memory usage again.
    second_reading = get_rss_mem_by_pid(firecracker_pid)

    # There should be a reduction of at least 10MB.
    assert first_reading - second_reading >= 10000
