# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that fail if network throughput does not obey rate limits."""
import time

from framework import utils
from host_tools import cpu_load

# The iperf version to run this tests with
IPERF_BINARY = "iperf3"

# Interval used by iperf to get maximum bandwidth
IPERF_TRANSMIT_TIME = 4

# Use a fixed-size TCP window so we get constant flow
IPERF_TCP_WINDOW = "256K"

# The rate limiting value
RATE_LIMIT_BYTES = 10485760

# The initial token bucket size
BURST_SIZE = 104857600

# The refill time for the token bucket
REFILL_TIME_MS = 100

RATE_LIMITER_NO_BURST = {
    "bandwidth": {"size": RATE_LIMIT_BYTES, "refill_time": REFILL_TIME_MS}
}
RATE_LIMITER_WITH_BURST = {
    "bandwidth": {
        "size": RATE_LIMIT_BYTES,
        "one_time_burst": BURST_SIZE,
        "refill_time": REFILL_TIME_MS,
    }
}


# Deltas that are accepted between expected values and achieved
# values throughout the tests
MAX_BYTES_DIFF_PERCENTAGE = 10
MAX_TIME_DIFF = 25


def test_tx_rate_limiting(uvm_plain):
    """
    Run iperf tx with and without rate limiting; check limiting effect.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.basic_config()

    # For this test we will be adding three interfaces:
    # 1. No rate limiting
    test_microvm.add_net_iface()
    # 2. Rate limiting without burst
    test_microvm.add_net_iface(tx_rate_limiter=RATE_LIMITER_NO_BURST)
    # 3. Rate limiting with burst
    test_microvm.add_net_iface(tx_rate_limiter=RATE_LIMITER_WITH_BURST)

    test_microvm.start()

    _check_tx_rate_limiting(test_microvm)
    _check_tx_rate_limit_patch(test_microvm)


def test_rx_rate_limiting(uvm_plain):
    """
    Run iperf rx with and without rate limiting; check limiting effect.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.basic_config()

    # For this test we will be adding three interfaces:
    # 1. No rate limiting
    test_microvm.add_net_iface()
    # 2. Rate limiting without burst
    test_microvm.add_net_iface(rx_rate_limiter=RATE_LIMITER_NO_BURST)
    # 3. Rate limiting with burst
    test_microvm.add_net_iface(rx_rate_limiter=RATE_LIMITER_WITH_BURST)

    # Start the microvm.
    test_microvm.start()

    _check_rx_rate_limiting(test_microvm)
    _check_rx_rate_limit_patch(test_microvm)


def test_rx_rate_limiting_cpu_load(uvm_plain):
    """
    Run iperf rx with rate limiting; verify cpu load is below threshold.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.basic_config()

    # Create interface with aggressive rate limiting enabled.
    rx_rate_limiter_no_burst = {
        "bandwidth": {"size": 65536, "refill_time": 1000}  # 64KBytes  # 1s
    }
    iface = test_microvm.add_net_iface(rx_rate_limiter=rx_rate_limiter_no_burst)

    test_microvm.start()

    # Start iperf server on guest.
    _start_iperf_server_on_guest(test_microvm, iface.guest_ip)

    # Run iperf client sending UDP traffic.
    iperf_cmd = "{} {} -u -c {} -b 1000000000 -t{} -f KBytes".format(
        test_microvm.netns.cmd_prefix(),
        IPERF_BINARY,
        iface.guest_ip,
        IPERF_TRANSMIT_TIME * 5,
    )

    # Enable monitor that checks if the cpu load is over the threshold.
    # After multiple runs, the average value for the cpu load
    # seems to be around 10%. Setting the threshold a little
    # higher to skip false positives.
    # We want to monitor the emulation thread, which is currently
    # the first one created.
    # A possible improvement is to find it by name.
    cpu_load_monitor = cpu_load.CpuLoadMonitor(
        process_pid=test_microvm.firecracker_pid,
        thread_pid=test_microvm.firecracker_pid,
        threshold=20,
    )
    with cpu_load_monitor:
        _run_iperf_on_host(iperf_cmd)


def _check_tx_rate_limiting(test_microvm):
    """Check that the transmit rate is within expectations."""
    eth0 = test_microvm.iface["eth0"]["iface"]
    eth1 = test_microvm.iface["eth1"]["iface"]
    eth2 = test_microvm.iface["eth2"]["iface"]

    # Start iperf server on the host as this is the tx rate limiting test.
    _start_iperf_server_on_host(test_microvm.netns.cmd_prefix())

    # First step: get the transfer rate when no rate limiting is enabled.
    # We are receiving the result in KBytes from iperf.
    print("Run guest TX iperf with no rate-limit")
    rate_no_limit_kbps = _get_tx_bandwidth_with_duration(
        test_microvm, eth0.guest_ip, eth0.host_ip, IPERF_TRANSMIT_TIME
    )
    print("TX rate_no_limit_kbps: {}".format(rate_no_limit_kbps))

    # Calculate the number of bytes that are expected to be sent
    # in each second once the rate limiting is enabled.
    expected_kbps = int(RATE_LIMIT_BYTES / (REFILL_TIME_MS / 1000.0) / 1024)
    print("Rate-Limit TX expected_kbps: {}".format(expected_kbps))

    # Sanity check that bandwidth with no rate limiting is at least double
    # than the one expected when rate limiting is in place.
    assert _get_percentage_difference(rate_no_limit_kbps, expected_kbps) > 100

    # Second step: check bandwidth when rate limiting is on.
    _check_tx_bandwidth(test_microvm, eth1.guest_ip, eth1.host_ip, expected_kbps)

    # Third step: get the number of bytes when rate limiting is on and there is
    # an initial burst size from where to consume.
    print("Run guest TX iperf with exact burst size")
    # Use iperf to obtain the bandwidth when there is burst to consume from,
    # send exactly BURST_SIZE packets.
    iperf_cmd = "{} -c {} -n {} -f KBytes -w {} -N".format(
        IPERF_BINARY, eth2.host_ip, BURST_SIZE, IPERF_TCP_WINDOW
    )
    iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, eth2.guest_ip)
    print(iperf_out)
    _, burst_kbps = _process_iperf_output(iperf_out)
    print("TX burst_kbps: {}".format(burst_kbps))
    # Test that the burst bandwidth is at least as two times the rate limit.
    assert _get_percentage_difference(burst_kbps, expected_kbps) > 100

    # Since the burst should be consumed, check rate limit is in place.
    _check_tx_bandwidth(test_microvm, eth2.guest_ip, eth2.host_ip, expected_kbps)


def _check_rx_rate_limiting(test_microvm):
    """Check that the receiving rate is within expectations."""
    eth0 = test_microvm.iface["eth0"]["iface"]
    eth1 = test_microvm.iface["eth1"]["iface"]
    eth2 = test_microvm.iface["eth2"]["iface"]

    # Start iperf server on guest.
    _start_iperf_server_on_guest(test_microvm, eth0.guest_ip)

    # First step: get the transfer rate when no rate limiting is enabled.
    # We are receiving the result in KBytes from iperf.
    print("Run guest RX iperf with no rate-limit")
    rate_no_limit_kbps = _get_rx_bandwidth_with_duration(
        test_microvm, eth0.guest_ip, IPERF_TRANSMIT_TIME
    )
    print("RX rate_no_limit_kbps: {}".format(rate_no_limit_kbps))

    # Calculate the number of bytes that are expected to be sent
    # in each second once the rate limiting is enabled.
    expected_kbps = int(RATE_LIMIT_BYTES / (REFILL_TIME_MS / 1000.0) / 1024)
    print("Rate-Limit RX expected_kbps: {}".format(expected_kbps))

    # Sanity check that bandwidth with no rate limiting is at least double
    # than the one expected when rate limiting is in place.
    assert _get_percentage_difference(rate_no_limit_kbps, expected_kbps) > 100

    # Second step: check bandwidth when rate limiting is on.
    _check_rx_bandwidth(test_microvm, eth1.guest_ip, expected_kbps)

    # Third step: get the number of bytes when rate limiting is on and there is
    # an initial burst size from where to consume.
    print("Run guest RX iperf with exact burst size")
    # Use iperf to obtain the bandwidth when there is burst to consume from,
    # send exactly BURST_SIZE packets.
    iperf_cmd = "{} {} -c {} -n {} -f KBytes -w {} -N".format(
        test_microvm.netns.cmd_prefix(),
        IPERF_BINARY,
        eth2.guest_ip,
        BURST_SIZE,
        IPERF_TCP_WINDOW,
    )
    iperf_out = _run_iperf_on_host(iperf_cmd)
    print(iperf_out)
    _, burst_kbps = _process_iperf_output(iperf_out)
    print("RX burst_kbps: {}".format(burst_kbps))
    # Test that the burst bandwidth is at least as two times the rate limit.
    assert _get_percentage_difference(burst_kbps, expected_kbps) > 100

    # Since the burst should be consumed, check rate limit is in place.
    _check_rx_bandwidth(test_microvm, eth2.guest_ip, expected_kbps)


def _check_tx_rate_limit_patch(test_microvm):
    """Patch the TX rate limiters and check the new limits."""
    eth0 = test_microvm.iface["eth0"]["iface"]
    eth1 = test_microvm.iface["eth1"]["iface"]
    bucket_size = int(RATE_LIMIT_BYTES * 2)
    expected_kbps = int(bucket_size / (REFILL_TIME_MS / 1000.0) / 1024)

    # Check that a TX rate limiter can be applied to a previously unlimited
    # interface.
    _patch_iface_bw(test_microvm, "eth0", "TX", bucket_size, REFILL_TIME_MS)
    _check_tx_bandwidth(test_microvm, eth0.guest_ip, eth0.host_ip, expected_kbps)

    # Check that a TX rate limiter can be updated.
    _patch_iface_bw(test_microvm, "eth1", "TX", bucket_size, REFILL_TIME_MS)
    _check_tx_bandwidth(test_microvm, eth1.guest_ip, eth1.host_ip, expected_kbps)

    # Check that a TX rate limiter can be removed.
    _patch_iface_bw(test_microvm, "eth0", "TX", 0, 0)
    rate_no_limit_kbps = _get_tx_bandwidth_with_duration(
        test_microvm, eth0.guest_ip, eth0.host_ip, IPERF_TRANSMIT_TIME
    )
    # Check that bandwidth when rate-limit disabled is at least 1.5x larger
    # than the one when rate limiting was enabled.
    assert _get_percentage_difference(rate_no_limit_kbps, expected_kbps) > 50


def _check_rx_rate_limit_patch(test_microvm):
    """Patch the RX rate limiters and check the new limits."""
    eth0 = test_microvm.iface["eth0"]["iface"]
    eth1 = test_microvm.iface["eth1"]["iface"]
    bucket_size = int(RATE_LIMIT_BYTES * 2)
    expected_kbps = int(bucket_size / (REFILL_TIME_MS / 1000.0) / 1024)

    # Check that an RX rate limiter can be applied to a previously unlimited
    # interface.
    _patch_iface_bw(test_microvm, "eth0", "RX", bucket_size, REFILL_TIME_MS)
    _check_rx_bandwidth(test_microvm, eth0.guest_ip, expected_kbps)

    # Check that an RX rate limiter can be updated.
    _patch_iface_bw(test_microvm, "eth1", "RX", bucket_size, REFILL_TIME_MS)
    _check_rx_bandwidth(test_microvm, eth1.guest_ip, expected_kbps)

    # Check that an RX rate limiter can be removed.
    _patch_iface_bw(test_microvm, "eth0", "RX", 0, 0)
    rate_no_limit_kbps = _get_rx_bandwidth_with_duration(
        test_microvm, eth0.guest_ip, IPERF_TRANSMIT_TIME
    )
    # Check that bandwidth when rate-limit disabled is at least 1.5x larger
    # than the one when rate limiting was enabled.
    assert _get_percentage_difference(rate_no_limit_kbps, expected_kbps) > 50


def _check_tx_bandwidth(test_microvm, guest_ip, host_ip, expected_kbps):
    """Check that the rate-limited TX bandwidth is close to what we expect.

    At this point, a daemonized iperf3 server is expected to be running on
    the host.
    """
    print("Check guest TX rate-limit; expected kbps {}".format(expected_kbps))
    observed_kbps = _get_tx_bandwidth_with_duration(
        test_microvm, guest_ip, host_ip, IPERF_TRANSMIT_TIME
    )

    diff_pc = _get_percentage_difference(observed_kbps, expected_kbps)
    print("TX calculated diff percentage: {}\n".format(diff_pc))

    if diff_pc >= MAX_BYTES_DIFF_PERCENTAGE:
        print("Short duration test failed. Try another run with 10x duration.")

        observed_kbps = _get_tx_bandwidth_with_duration(
            test_microvm, guest_ip, host_ip, 10 * IPERF_TRANSMIT_TIME
        )
        diff_pc = _get_percentage_difference(observed_kbps, expected_kbps)
        print("TX calculated diff percentage: {}\n".format(diff_pc))

        assert diff_pc < MAX_BYTES_DIFF_PERCENTAGE


def _get_tx_bandwidth_with_duration(test_microvm, guest_ip, host_ip, duration):
    """Check that the rate-limited TX bandwidth is close to what we expect."""
    iperf_cmd = "{} -c {} -t {} -f KBytes -w {} -N".format(
        IPERF_BINARY, host_ip, duration, IPERF_TCP_WINDOW
    )

    iperf_out = _run_iperf_on_guest(test_microvm, iperf_cmd, guest_ip)
    print(iperf_out)

    _, observed_kbps = _process_iperf_output(iperf_out)
    print("TX observed_kbps: {}".format(observed_kbps))
    return observed_kbps


def _check_rx_bandwidth(test_microvm, guest_ip, expected_kbps):
    """Check that the rate-limited RX bandwidth is close to what we expect.

    At this point, a daemonized iperf3 server is expected to be running on
    the guest.
    """
    print("Check guest RX rate-limit; expected kbps {}".format(expected_kbps))
    observed_kbps = _get_rx_bandwidth_with_duration(
        test_microvm, guest_ip, IPERF_TRANSMIT_TIME
    )

    diff_pc = _get_percentage_difference(observed_kbps, expected_kbps)
    print("RX calculated diff percentage: {}\n".format(diff_pc))

    if diff_pc >= MAX_BYTES_DIFF_PERCENTAGE:
        print("Short duration test failed. Try another run with 10x duration.")

        observed_kbps = _get_rx_bandwidth_with_duration(
            test_microvm, guest_ip, 10 * IPERF_TRANSMIT_TIME
        )
        diff_pc = _get_percentage_difference(observed_kbps, expected_kbps)
        print("TX calculated diff percentage: {}\n".format(diff_pc))

        assert diff_pc < MAX_BYTES_DIFF_PERCENTAGE


def _get_rx_bandwidth_with_duration(test_microvm, guest_ip, duration):
    """Check that the rate-limited RX bandwidth is close to what we expect."""
    iperf_cmd = "{} {} -c {} -t {} -f KBytes -w {} -N".format(
        test_microvm.netns.cmd_prefix(),
        IPERF_BINARY,
        guest_ip,
        duration,
        IPERF_TCP_WINDOW,
    )
    iperf_out = _run_iperf_on_host(iperf_cmd)
    print(iperf_out)

    _, observed_kbps = _process_iperf_output(iperf_out)
    print("RX observed_kbps: {}".format(observed_kbps))
    return observed_kbps


def _patch_iface_bw(test_microvm, iface_id, rx_or_tx, new_bucket_size, new_refill_time):
    """Update the bandwidth rate limiter for a given interface.

    Update the `rx_or_tx` rate limiter, on interface `iface_id` to the
    new `bucket_size`.
    """
    assert rx_or_tx in ["RX", "TX"]
    args = {
        "iface_id": iface_id,
        "{}_rate_limiter".format(rx_or_tx.lower()): {
            "bandwidth": {"size": new_bucket_size, "refill_time": new_refill_time}
        },
    }
    test_microvm.api.network.patch(**args)


def _start_iperf_server_on_guest(test_microvm, hostname):
    """Start iperf in server mode through an SSH connection."""
    test_microvm.guest_ip = hostname

    iperf_cmd = "{} -sD -f KBytes\n".format(IPERF_BINARY)
    test_microvm.ssh.run(iperf_cmd)

    # Wait for the iperf daemon to start.
    time.sleep(1)


def _run_iperf_on_guest(test_microvm, iperf_cmd, hostname):
    """Run a client related iperf command through an SSH connection."""
    test_microvm.guest_ip = hostname
    return test_microvm.ssh.check_output(iperf_cmd).stdout


def _start_iperf_server_on_host(netns_cmd_prefix):
    """Start iperf in server mode after killing any leftover iperf daemon."""
    iperf_cmd = "pkill {}\n".format(IPERF_BINARY)

    # Don't check the result of this command because it can fail if no iperf
    # is running.
    utils.run_cmd(iperf_cmd)

    iperf_cmd = "{} {} -sD -f KBytes\n".format(netns_cmd_prefix, IPERF_BINARY)

    utils.check_output(iperf_cmd)

    # Wait for the iperf daemon to start.
    time.sleep(1)


def _run_iperf_on_host(iperf_cmd):
    """Execute a client related iperf command locally."""
    code, stdout, stderr = utils.check_output(iperf_cmd)
    assert code == 0, f"stdout: {stdout}\nstderr: {stderr}"

    return stdout


def _get_percentage_difference(measured, base):
    """Return the percentage delta between the arguments."""
    if measured == base:
        return 0
    try:
        return (abs(measured - base) / base) * 100.0
    except ZeroDivisionError:
        # It means base and only base is 0.
        return 100.0


def _process_iperf_line(line):
    """Parse iperf3 summary line and return test time and bandwidth."""
    test_time = line.split("  ")[2].split("-")[1].strip().split(" ")[0]
    test_bw = line.split("  ")[5].split(" ")[0].strip()
    return float(test_time), float(test_bw)


def _process_iperf_output(iperf_out):
    """Parse iperf3 output and return average test time and bandwidth."""
    iperf_out_lines = iperf_out.splitlines()
    for line in iperf_out_lines:
        if line.find("sender") != -1:
            send_time, send_bw = _process_iperf_line(line)
        if line.find("receiver") != -1:
            rcv_time, rcv_bw = _process_iperf_line(line)
    iperf_out_time = (send_time + rcv_time) / 2.0
    iperf_out_bw = (send_bw + rcv_bw) / 2.0
    return float(iperf_out_time), float(iperf_out_bw)
