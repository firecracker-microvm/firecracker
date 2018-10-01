"""
Tests that ensure the boot time to init process is within spec.
"""
import time
import pytest
import re
import host_tools.logging as log_tools

MAX_BOOT_TIME_US = 150000
""" The maximum acceptable boot time in us. """
# TODO: Keep a `current` boot time in S3 and validate we don't regress


@pytest.mark.timeout(120)
def test_microvm_boottime_no_network(test_microvm_with_boottime):
    """Check guest boottime of microvm without network."""
    boottime_us = _test_microvm_boottime(test_microvm_with_boottime, None)
    print("Boot time with no network is: " + str(boottime_us) + " us")


def test_microvm_boottime_with_network(
        test_microvm_with_boottime,
        network_config
):
    """Check guest boottime of microvm with network."""
    boottime_us = _test_microvm_boottime(
        test_microvm_with_boottime,
        network_config
    )
    print("Boot time with network configured is: " + str(boottime_us) + " us")


def _test_microvm_boottime(
        microvm,
        net_config
):
    """
    Asserts that we meet the minimum boot time. Should use a Microvm with the
    `boottime` capability.
    """

    microvm.basic_config(
        vcpu_count=2,
        mem_size_mib=1024,
        net_iface_count=0,
        log_enable=False
    )
    if net_config:
        microvm.basic_network_config(net_config)
    microvm.logger_config("Warning", False, False)

    microvm.start()
    time.sleep(0.4)
    lines = log_tools.sequential_fifo_reader(microvm, 0, 20)

    TIMESTAMP_LOG_REGEX = r'Guest-boot-time\ \=\ (\d+)'
    boot_time_us = 0
    for line in lines:
        timestamps = re.findall(TIMESTAMP_LOG_REGEX, line)
        if timestamps:
            boot_time_us = int(timestamps[0])

    assert boot_time_us > 0
    assert boot_time_us < MAX_BOOT_TIME_US
    return boot_time_us
