# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-rng device"""

import pytest

from framework.utils import check_entropy
from host_tools.network import SSHConnection


def uvm_with_rng_booted(microvm_factory, guest_kernel, rootfs, rate_limiter):
    """Return a booted microvm with virtio-rng configured"""
    uvm = microvm_factory.build(guest_kernel, rootfs)
    uvm.spawn(log_level="INFO")
    uvm.basic_config(vcpu_count=2, mem_size_mib=256)
    uvm.add_net_iface()
    uvm.api.entropy.put(rate_limiter=rate_limiter)
    uvm.start()
    # Just stuff it in the microvm so we can look at it later
    uvm.rng_rate_limiter = rate_limiter
    return uvm


def uvm_with_rng_restored(microvm_factory, guest_kernel, rootfs, rate_limiter):
    """Return a restored uvm with virtio-rng configured"""
    uvm = uvm_with_rng_booted(microvm_factory, guest_kernel, rootfs, rate_limiter)
    snapshot = uvm.snapshot_full()
    uvm.kill()
    uvm2 = microvm_factory.build_from_snapshot(snapshot)
    uvm2.rng_rate_limiter = uvm.rng_rate_limiter
    return uvm2


@pytest.fixture(params=[uvm_with_rng_booted, uvm_with_rng_restored])
def uvm_ctor(request):
    """Fixture to return uvms with different constructors"""
    return request.param


@pytest.fixture(params=[None])
def rate_limiter(request):
    """Fixture to return different rate limiters"""
    return request.param


@pytest.fixture
def uvm_any(microvm_factory, uvm_ctor, guest_kernel, rootfs, rate_limiter):
    """Return booted and restored uvms"""
    return uvm_ctor(microvm_factory, guest_kernel, rootfs, rate_limiter)


def list_rng_available(ssh_connection: SSHConnection) -> list[str]:
    """Returns a list of rng devices available in the VM"""
    return (
        ssh_connection.check_output("cat /sys/class/misc/hw_random/rng_available")
        .stdout.strip()
        .split()
    )


def get_rng_current(ssh_connection: SSHConnection) -> str:
    """Returns the current rng device used by hwrng"""
    return ssh_connection.check_output(
        "cat /sys/class/misc/hw_random/rng_current"
    ).stdout.strip()


def assert_virtio_rng_is_current_hwrng_device(ssh_connection: SSHConnection):
    """Asserts that virtio_rng is the current device used by hwrng"""
    # we expect something like virtio_rng.0
    assert get_rng_current(ssh_connection).startswith(
        "virtio_rng"
    ), "virtio_rng device should be the current used by hwrng"


def test_rng_not_present(uvm_nano):
    """
    Test a guest microVM *without* an entropy device and ensure that
    we cannot get data from /dev/hwrng
    """

    vm = uvm_nano
    vm.add_net_iface()
    vm.start()

    assert not any(
        rng.startswith("virtio_rng") for rng in list_rng_available(vm.ssh)
    ), "virtio_rng device should not be available in the uvm"


def test_rng_present(uvm_any):
    """
    Test a guest microVM with an entropy defined configured and ensure
    that we can access `/dev/hwrng`
    """

    vm = uvm_any
    assert_virtio_rng_is_current_hwrng_device(vm.ssh)
    check_entropy(vm.ssh)


def _get_percentage_difference(measured, base):
    """Return the percentage delta between the arguments."""
    if measured == base:
        return 0
    try:
        return ((measured - base) / base) * 100.0
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
    _, _, stderr = ssh.check_output(cmd)

    # dd gives its output on stderr
    return _process_dd_output(stderr)


def _check_entropy_rate_limited(ssh, random_bytes, expected_kbps):
    """
    Ask for `random_bytes` from `/dev/hwrng` in the guest and check
    that achieved throughput does not exceed the expected throughput by
    more than 2%.

    NOTE: 2% is accounting for the initial credits available in the buckets
    which can be consumed immediately. In the `dd` command we read `size * 100`
    bytes, where `size` is the size of the bucket. As a result, the first
    `size` bytes will be read "immediately" and the remaining `99 * size` bytes
    will be read at a rate of `size / refill_time`. So, the total test runtime
    will be `99 * refill_time`. That helps us calculate the expected throughput
    allowed from our rate limiter like this:

    size * 100 / (99 * refill_time) =
    (100 / 99) * (size / refill_time) =
    (100 / 99) * expected_throughput_rate =
    1.01 * expected_throughput_rate

    (kudos to @roypat for this analysis)

    So, we should expect a 1% margin from the expected throughput. We use 2%
    for accounting for rounding/measurements errors.
    """
    measured_kbps = _get_throughput(ssh, random_bytes)
    assert (
        _get_percentage_difference(measured_kbps, expected_kbps) <= 2
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
    "rate_limiter",
    [
        {"bandwidth": {"size": 1000, "refill_time": 100}},
        {"bandwidth": {"size": 10000, "refill_time": 100}},
        {"bandwidth": {"size": 100000, "refill_time": 100}},
    ],
    indirect=True,
    ids=_rate_limiter_id,
)
@pytest.mark.parametrize("uvm_ctor", [uvm_with_rng_booted], indirect=True)
def test_rng_bw_rate_limiter(uvm_any):
    """
    Test that rate limiter without initial burst budget works
    """
    vm = uvm_any
    size = vm.rng_rate_limiter["bandwidth"]["size"]
    refill_time = vm.rng_rate_limiter["bandwidth"]["refill_time"]
    expected_kbps = size / refill_time

    assert_virtio_rng_is_current_hwrng_device(vm.ssh)
    # Check the rate limiter using a request size equal to the size
    # of the token bucket.
    _check_entropy_rate_limited(vm.ssh, size, expected_kbps)
