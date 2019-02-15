# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that fail if network throughput does not obey rate limits."""
import time

from subprocess import run, PIPE

import host_tools.network as net_tools  # pylint: disable=import-error

# The iperf version to run this tests with
IPERF_BINARY = 'iperf3'

# Interval used by iperf to get maximum bandwidth
IPERF_TRANSMIT_TIME = 3

# The rate limiting value
RATE_LIMIT_BYTES = 10485760

# The initial token bucket size
BURST_SIZE = 1048576000

# The refill time for the token bucket
RATE_LIMIT_REFILL_TIME = 100

# Deltas that are accepted between expected values and achieved
# values throughout the tests
MAX_BYTES_DIFF_PERCENTAGE = 10
MAX_TIME_DIFF = 25


def test_tx_rate_limiting(test_microvm_with_ssh, network_config):
    """Run iperf tx with and without rate limiting; check limiting effect."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config()

    # For this test we will be adding three interfaces:
    # 1. No rate limiting
    # 2. Rate limiting without burst
    # 3. Rate limiting with burst
    host_ips = ['', '', '']
    guest_ips = ['', '', '']

    iface_id = '1'
    # Create tap before configuring interface.
    _tap1, host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        iface_id
    )
    guest_ips[0] = guest_ip
    host_ips[0] = host_ip

    iface_id = '2'
    tx_rate_limiter_no_burst = {
        'bandwidth': {
            'size': RATE_LIMIT_BYTES,
            'refill_time': RATE_LIMIT_REFILL_TIME
        }
    }
    _tap2, host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        iface_id,
        tx_rate_limiter=tx_rate_limiter_no_burst
    )
    guest_ips[1] = guest_ip
    host_ips[1] = host_ip

    iface_id = '3'
    tx_rate_limiter_with_burst = {
        'bandwidth': {
            'size': RATE_LIMIT_BYTES,
            'one_time_burst': BURST_SIZE,
            'refill_time': RATE_LIMIT_REFILL_TIME
        }
    }
    _tap3, host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        iface_id,
        tx_rate_limiter=tx_rate_limiter_with_burst
    )
    guest_ips[2] = guest_ip
    host_ips[2] = host_ip

    test_microvm.start()

    _check_tx_rate_limiting(test_microvm, guest_ips, host_ips)
    _check_tx_rate_limit_patch(test_microvm, guest_ips, host_ips)


def test_rx_rate_limiting(test_microvm_with_ssh, network_config):
    """Run iperf rx with and without rate limiting; check limiting effect."""
    test_microvm = test_microvm_with_ssh
    test_microvm.spawn()

    test_microvm.basic_config()

    # For this test we will be adding three interfaces:
    # 1. No rate limiting
    # 2. Rate limiting without burst
    # 3. Rate limiting with burst
    host_ips = ['', '', '']
    guest_ips = ['', '', '']

    iface_id = '1'
    # Create tap before configuring interface.
    _tap1, host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        iface_id
    )
    guest_ips[0] = guest_ip
    host_ips[0] = host_ip

    iface_id = '2'
    rx_rate_limiter_no_burst = {
        'bandwidth': {
            'size': RATE_LIMIT_BYTES,
            'refill_time': RATE_LIMIT_REFILL_TIME
        }
    }
    _tap2, host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        iface_id,
        rx_rate_limiter=rx_rate_limiter_no_burst
    )
    guest_ips[1] = guest_ip
    host_ips[1] = host_ip

    iface_id = '3'
    rx_rate_limiter_no_burst = {
        'bandwidth': {
            'size': RATE_LIMIT_BYTES,
            'one_time_burst': BURST_SIZE,
            'refill_time': RATE_LIMIT_REFILL_TIME
        }
    }
    _tap3, host_ip, guest_ip = test_microvm.ssh_network_config(
        network_config,
        iface_id,
        rx_rate_limiter=rx_rate_limiter_no_burst
    )
    guest_ips[2] = guest_ip
    host_ips[2] = host_ip

    # Start the microvm.
    test_microvm.start()

    _check_rx_rate_limiting(test_microvm, guest_ips)
    _check_rx_rate_limit_patch(test_microvm, guest_ips)


def _check_tx_rate_limiting(test_microvm, guest_ips, host_ips):
    """Check that the transmit rate is within expectations."""
    # Start iperf on the host as this is the tx rate limiting test.
    _start_local_iperf(test_microvm.jailer.netns_cmd_prefix())

    # First step: get the transfer rate when no rate limiting is enabled.
    # We are receiving the result in KBytes from iperf; 1000 converts to Bytes.
    iperf_cmd = '{} -c {} -t{} -f KBytes'.format(
        IPERF_BINARY,
        host_ips[0],
        IPERF_TRANSMIT_TIME
    )

    iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ips[0])
    iperf_out = _process_iperf_output(iperf_out)[1]

    rate_no_limit_bytes = 1000 * float(iperf_out)

    # Second step: get the number of bytes when rate limiting is on.

    # Calculate the number of bytes that are expected to be sent
    # in each second once the rate limiting is enabled.
    rate_limit_bps = 1000 * RATE_LIMIT_BYTES / float(RATE_LIMIT_REFILL_TIME)

    # Use iperf for some number of seconds to get the number of bytes it sent
    # with rate limiting on.
    iperf_cmd = '{} -c {} -t{} -f KBytes'.format(
        IPERF_BINARY,
        host_ips[1],
        IPERF_TRANSMIT_TIME
    )
    iperf_out = _run_iperf_on_guest(
        test_microvm, iperf_cmd, guest_ips[1]
    )
    iperf_out = _process_iperf_output(iperf_out)[1]

    rate_limit_bytes_achieved = 1000 * float(iperf_out)
    rate_limit_bytes_expected = rate_limit_bps

    # Assert on the bytes expected and achieved with rate limiting on; we are
    # expecting a difference no bigger than MAX_RATE_LIMIT_BYTES_DIFF
    assert (
            _get_difference(
                rate_limit_bytes_achieved,
                rate_limit_bytes_expected
            )
            < MAX_BYTES_DIFF_PERCENTAGE
    )

    # Third step: get the number of bytes when rate limiting is on and there is
    # an initial burst size from where to consume.

    # Use iperf to obtain the bandwidth when there is burst to consume from.
    iperf_cmd = '{} -c {} -n{} -f KBytes'.format(
        IPERF_BINARY,
        host_ips[2],
        BURST_SIZE
    )
    iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ips[2])
    # iperf will give variable number of output lines depending on how much
    # time it took to send the amount specified.
    burst_bw_first_time_achieved = _process_iperf_output(iperf_out)[1]

    # The second time we use iperf to send bytes we need to see that the burst
    # was consumed and that the transmit rate is now equal to the rate limit.
    # We are sending the amount of bytes that can be sent in 1 sec with rate
    # limiting enabled.
    iperf_cmd = '{} -c {} -n{} -f KBytes'.format(
        IPERF_BINARY, host_ips[2], rate_limit_bps
    )
    iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ips[2])
    iperf_out_time, iperf_out_bw = _process_iperf_output(iperf_out)

    # Test that the bandwidth we obtained first time is at least as two times
    # higher than the one obtained when rate limiting is on.
    assert _get_difference(burst_bw_first_time_achieved, iperf_out_bw) > 100
    # Test that the bandwidth we obtained second time is at least two times
    # lower than the one obtained when no rate limiting is in place.
    assert _get_difference(rate_no_limit_bytes, iperf_out_bw) > 100

    burst_consumed_time_achieved = iperf_out_time
    # We expect it to take around 1 sec now.
    burst_consumed_time_expected = 1

    assert (
            _get_difference(
                burst_consumed_time_achieved,
                burst_consumed_time_expected
            )
            < MAX_TIME_DIFF
    )


def _check_rx_rate_limiting(test_microvm, guest_ips):
    """Check that the receiving rate is within expectations."""
    # Start iperf on guest.
    _start_iperf_on_guest(test_microvm, guest_ips[0])

    # First step: get the transfer rate when no rate limiting is enabled.
    # We are receiving the result in KBytes from iperf; 1000 converts to Bytes.
    iperf_cmd = '{} {} -c {} -t{} -f KBytes'.format(
        test_microvm.jailer.netns_cmd_prefix(),
        IPERF_BINARY,
        guest_ips[0],
        IPERF_TRANSMIT_TIME
    )
    iperf_out = _run_local_iperf(iperf_cmd)
    iperf_out = _process_iperf_output(iperf_out)[1]

    rate_no_limit_bytes = float(iperf_out)

    # Second step: get the number of bytes when rate limiting is on.

    # Calculate the number of bytes that are expected to be sent
    # in each second once the rate limiting is enabled.
    rate_limit_bps = 1000 * RATE_LIMIT_BYTES / float(RATE_LIMIT_REFILL_TIME)

    # Use iperf for 2 seconds to get the number of bytes it sent with rate
    # limiting on.
    iperf_cmd = '{} {} -c {} -t{} -f KBytes'.format(
        test_microvm.jailer.netns_cmd_prefix(),
        IPERF_BINARY,
        guest_ips[1],
        IPERF_TRANSMIT_TIME
    )
    iperf_out = _run_local_iperf(iperf_cmd)
    iperf_out = _process_iperf_output(iperf_out)[1]
    rate_limit_bytes_achieved = 1000 * float(iperf_out)
    rate_limit_bytes_expected = rate_limit_bps

    # Assert on the bytes expected and achieved with rate limiting on; we are
    # expecting a difference no bigger than MAX_RATE_LIMIT_BYTES_DIFF
    assert (
            _get_difference(
                rate_limit_bytes_achieved,
                rate_limit_bytes_expected
            )
            < MAX_BYTES_DIFF_PERCENTAGE
    )

    # Third step: get the number of bytes when rate limiting is on and there is
    # an initial burst size from where to consume.

    # Use iperf to obtain the time interval that a BURST_SIZE (way larger
    # than the bucket's size) can be sent over the network.
    iperf_cmd = '{} {} -c {} -n{} -f KBytes'.format(
        test_microvm.jailer.netns_cmd_prefix(),
        IPERF_BINARY,
        guest_ips[2],
        BURST_SIZE)
    iperf_out = _run_local_iperf(iperf_cmd)

    # iperf will give variable number of output lines depending on how much
    # time it took to send the amount specified.
    burst_bw_first_time_achieved = _process_iperf_output(iperf_out)[1]

    # The second time we use iperf to send bytes we need to see that the burst
    # was consumed and that the transmit rate is now equal to the rate limit.
    # We are sending the amount of bytes that can be sent in 1 sec with rate
    # rate limiting enabled.
    iperf_cmd = '{} {} -c {} -n{} -f KBytes'.format(
        test_microvm.jailer.netns_cmd_prefix(),
        IPERF_BINARY,
        guest_ips[2],
        rate_limit_bps
    )
    iperf_out = _run_local_iperf(iperf_cmd)
    iperf_out_time, iperf_out_bw = _process_iperf_output(iperf_out)

    # Test that the bandwidth we obtained first time is at least two times
    # higher than the one obtained when rate limiting is on.
    assert _get_difference(burst_bw_first_time_achieved, iperf_out_bw) > 100
    # Test that the bandwidth we obtained second time is at least two times
    # lower than the one obtained when no rate limiting is in place.
    assert _get_difference(rate_no_limit_bytes, iperf_out_bw) > 100

    burst_consumed_time_achieved = iperf_out_time
    # We expect it to take around 1 sec now.
    burst_consumed_time_expected = 1

    assert (
            _get_difference(
                burst_consumed_time_achieved,
                burst_consumed_time_expected
            )
            < MAX_TIME_DIFF
    )


def _check_tx_rate_limit_patch(test_microvm, guest_ips, host_ips):
    """Patch the TX rate limiters and check the new limits."""
    bucket_size = int(RATE_LIMIT_BYTES / 2)
    bandwidth_kb = int(bucket_size / (RATE_LIMIT_REFILL_TIME/1000.0) / 1024)

    # Check that a TX rate limiter can be applied to a previously unlimited
    # interface.
    _patch_iface_bw(test_microvm, "1", "TX", bucket_size)
    _check_tx_bandwidth(test_microvm, guest_ips[0], host_ips[0], bandwidth_kb)

    # Check that a TX rate limiter can be updated.
    _patch_iface_bw(test_microvm, "2", "TX", bucket_size)
    _check_tx_bandwidth(test_microvm, guest_ips[1], host_ips[1], bandwidth_kb)


def _check_rx_rate_limit_patch(test_microvm, guest_ips):
    """Patch the RX rate limiters and check the new limits."""
    bucket_size = int(RATE_LIMIT_BYTES / 2)
    bandwidth_kb = int(bucket_size / (RATE_LIMIT_REFILL_TIME/1000.0) / 1024)

    # Check that an RX rate limiter can be applied to a previously unlimited
    # interface.
    _patch_iface_bw(test_microvm, "1", "RX", bucket_size)
    _check_rx_bandwidth(test_microvm, guest_ips[0], bandwidth_kb)

    # Check that an RX rate limiter can be updated.
    _patch_iface_bw(test_microvm, "2", "RX", bucket_size)
    _check_rx_bandwidth(test_microvm, guest_ips[1], bandwidth_kb)


def _check_tx_bandwidth(
        test_microvm,
        guest_ip,
        host_ip,
        expected_bw_kb
):
    """Check that the rate-limited TX bandwidth is close to what we expect.

    At this point, a daemonized iperf3 server is expected to be running on
    the host.
    """
    iperf_cmd = "{} -c {} -t {} -f KBytes".format(
        IPERF_BINARY,
        host_ip,
        IPERF_TRANSMIT_TIME
    )

    iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ip)
    _, observed_bw = _process_iperf_output(iperf_out)

    diff_pc = _get_difference(observed_bw, expected_bw_kb)
    assert diff_pc < MAX_BYTES_DIFF_PERCENTAGE


def _check_rx_bandwidth(
        test_microvm,
        guest_ip,
        expected_bw_kb
):
    """Check that the rate-limited RX bandwidth is close to what we expect.

    At this point, a daemonized iperf3 server is expected to be running on
    the guest.
    """
    iperf_cmd = "{} {} -c {} -t {} -f KBytes".format(
        test_microvm.jailer.netns_cmd_prefix(),
        IPERF_BINARY,
        guest_ip,
        IPERF_TRANSMIT_TIME
    )
    iperf_out = _run_local_iperf(iperf_cmd)
    _, observed_bw = _process_iperf_output(iperf_out)

    diff_pc = _get_difference(observed_bw, expected_bw_kb)
    assert diff_pc < MAX_BYTES_DIFF_PERCENTAGE


def _patch_iface_bw(test_microvm, iface_id, rx_or_tx, new_bucket_size):
    """Update the bandwidth rate limiter for a given interface.

    Update the `rx_or_tx` rate limiter, on interface `iface_id` to the
    new `bucket_size`.
    """
    assert rx_or_tx in ['RX', 'TX']
    args = {
        'iface_id': iface_id,
        "{}_rate_limiter".format(rx_or_tx.lower()): {
            'bandwidth': {
                'size': new_bucket_size,
                'refill_time': RATE_LIMIT_REFILL_TIME
            }
        }
    }
    resp = test_microvm.network.patch(**args)
    assert test_microvm.api_session.is_status_no_content(resp.status_code)


def _start_iperf_on_guest(test_microvm, hostname):
    """Start iperf in server mode through an SSH connection."""
    test_microvm.ssh_config['hostname'] = hostname
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    iperf_cmd = '{} -sD -f KBytes\n'.format(IPERF_BINARY)
    ssh_connection.execute_command(iperf_cmd)

    # Wait for the iperf daemon to start.
    time.sleep(2)
    ssh_connection.close()


def _run_iperf_on_guest(test_microvm, iperf_cmd, hostname):
    """Run a client related iperf command through an SSH connection."""
    test_microvm.ssh_config['hostname'] = hostname
    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    _, stdout, stderr = ssh_connection.execute_command(iperf_cmd)
    assert stderr.read().decode('utf-8') == ''

    out = stdout.read().decode('utf-8')
    ssh_connection.close()
    return out


def _start_local_iperf(netns_cmd_prefix):
    """Start iperf in server mode after killing any leftover iperf daemon."""
    iperf_cmd = 'pkill {}\n'.format(IPERF_BINARY)

    run(iperf_cmd, shell=True)

    iperf_cmd = '{} {} -sD -f KBytes\n'.format(netns_cmd_prefix, IPERF_BINARY)

    run(iperf_cmd, shell=True)

    # Wait for the iperf daemon to start.
    time.sleep(2)


def _run_local_iperf(iperf_cmd):
    """Execute a client related iperf command locally."""
    process = run(iperf_cmd, shell=True, stdout=PIPE)
    return process.stdout.decode('utf-8')


def _get_difference(current, previous):
    """Return the percentage delta between the arguments."""
    if current == previous:
        return 0
    try:
        return (abs(current - previous) / previous) * 100.0
    except ZeroDivisionError:
        # It means previous and only previous is 0.
        return 100.0


def _process_iperf_output(iperf_out):
    """Parse iperf 3 output and return test time and bandwidth."""
    found_line = 0
    iperf_out_lines = iperf_out.splitlines()
    for line in iperf_out_lines:
        if line.find('- - - - - - - -') != -1:
            found_line += 1

        if found_line == 3:
            iperf_out_time = line.split('  ')[2].split(
                '-'
            )[1].strip().split(" ")[0]
            iperf_out_bw = line.split('  ')[5].split(
                ' '
            )[0].strip()
            break
        elif found_line > 0:
            found_line += 1
    return float(iperf_out_time), float(iperf_out_bw)
