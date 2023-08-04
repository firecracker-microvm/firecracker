# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-rng device"""

# pylint:disable=redefined-outer-name

import pytest

from framework.properties import global_props
from framework.utils import check_entropy

if global_props.instance == "c7g.metal" and global_props.host_linux_version == "4.14":
    pytestmark = pytest.mark.skip(reason="c7g requires no SVE 5.10 kernel")


@pytest.fixture(params=[None])
def uvm_with_rng(uvm_nano, request):
    """Fixture of a microvm with virtio-rng configured"""
    rate_limiter = request.param
    uvm_nano.add_net_iface()
    uvm_nano.api.entropy.put(rate_limiter=rate_limiter)
    uvm_nano.start()
    # Just stuff it in the microvm so we can look at it later
    uvm_nano.rng_rate_limiter = rate_limiter
    return uvm_nano


def test_rng_not_present(uvm_nano):
    """
    Test a guest microVM *without* an entropy device and ensure that
    we cannot get data from /dev/hwrng
    """

    vm = uvm_nano
    vm.add_net_iface()
    vm.start()

    # If the guest kernel has been built with the virtio-rng module
    # the device should exist in the guest filesystem but we should
    # not be able to get random numbers out of it.
    cmd = "test -e /dev/hwrng"
    ecode, _, _ = vm.ssh.run(cmd)
    assert ecode == 0

    cmd = "dd if=/dev/hwrng of=/dev/null bs=10 count=1"
    ecode, _, _ = vm.ssh.run(cmd)
    assert ecode == 1


def test_rng_present(uvm_with_rng):
    """
    Test a guest microVM with an entropy defined configured and ensure
    that we can access `/dev/hwrng`
    """

    vm = uvm_with_rng
    check_entropy(vm.ssh)


def test_rng_snapshot(uvm_with_rng, microvm_factory):
    """
    Test that a virtio-rng device is functional after resuming from
    a snapshot
    """

    vm = uvm_with_rng
    check_entropy(vm.ssh)
    snapshot = vm.snapshot_full()

    new_vm = microvm_factory.build()
    new_vm.spawn()
    new_vm.restore_from_snapshot(snapshot, resume=True)
    check_entropy(new_vm.ssh)


def _get_percentage_difference(measured, base):
    """Return the percentage delta between the arguments."""
    if measured == base:
        return 0
    try:
        return (abs(measured - base) / base) * 100.0
    except ZeroDivisionError:
        # It means base and only base is 0.
        return 100.0


def _throughput_units_multiplier(units):
    """
    Parse the throughput units and return the multiplier that would
    translate the corresponding value to Bytes/sec
    """
    if units == "kB/s":
        return 1000

    if units == "MB/s":
        return 1000 * 1000

    if units == "GB/s":
        return 1000 * 1000 * 1000

    raise Exception("Unknown units")


def _process_dd_output(out):
    """
    Parse the output of `dd` and return the achieved throughput in
    KB/sec.
    """

    # Example `dd` output:
    #
    # $ dd if=/dev/hwrng of=/dev/null bs=100 count=1
    # 1+0 records in
    # 1+0 records out
    # 100 bytes (100 B) copied, 0.000749912 s, 133 kB/s

    # So we split the lines of the output and keep the last line.
    report = out.splitlines()[-1].split(" ")

    # Last two items in the line are value and units
    (value, units) = (report[-2], report[-1])

    return float(value) * _throughput_units_multiplier(units) / 1000


def _get_throughput(ssh, random_bytes):
    """
    Request `random_bytes` from `/dev/hwrng` and return the achieved
    throughput in KB/sec
    """

    # Issue a `dd` command to request 100 times `random_bytes` from the device.
    # 100 here is used to get enough confidence on the achieved throughput.
    cmd = "dd if=/dev/hwrng of=/dev/null bs={} count=100".format(random_bytes)
    exit_code, _, stderr = ssh.run(cmd)
    assert exit_code == 0, stderr

    # dd gives its output on stderr
    return _process_dd_output(stderr)


def _check_entropy_rate_limited(ssh, random_bytes, expected_kbps):
    """
    Ask for `random_bytes` from `/dev/hwrng` in the guest and check
    that achieved throughput is within a 10% of the expected throughput.

    NOTE: 10% is an arbitrarily selected limit which should be safe enough,
    so that we don't run into many intermittent CI failures.
    """
    measured_kbps = _get_throughput(ssh, random_bytes)
    assert (
        _get_percentage_difference(measured_kbps, expected_kbps) <= 10
    ), "Expected {} KB/s, measured {} KB/s".format(expected_kbps, measured_kbps)


def _rate_limiter_id(rate_limiter):
    """
    Helper function to return a name for the rate_limiter to be
    used as an id for parametrized tests.
    """
    size = rate_limiter["bandwidth"]["size"]
    refill_time = rate_limiter["bandwidth"]["refill_time"]

    return "{} KB/sec".format(float(size) / float(refill_time))


# parametrize the RNG rate limiter
@pytest.mark.parametrize(
    "uvm_with_rng",
    [
        {"bandwidth": {"size": 1000, "refill_time": 100}},
        {"bandwidth": {"size": 10000, "refill_time": 100}},
        {"bandwidth": {"size": 100000, "refill_time": 100}},
    ],
    indirect=True,
    ids=_rate_limiter_id,
)
def test_rng_bw_rate_limiter(uvm_with_rng):
    """
    Test that rate limiter without initial burst budget works
    """
    vm = uvm_with_rng
    # _start_vm_with_rng(vm, rate_limiter)

    size = vm.rng_rate_limiter["bandwidth"]["size"]
    refill_time = vm.rng_rate_limiter["bandwidth"]["refill_time"]

    expected_kbps = size / refill_time

    # Check the rate limiter using a request size equal to the size
    # of the token bucket.
    _check_entropy_rate_limited(vm.ssh, size, expected_kbps)
