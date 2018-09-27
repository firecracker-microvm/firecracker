"""
Tests that ensure the boot time to init process is within spec.
"""
import os
import re
import time

import pytest

import host_tools.logging as log_tools

# The maximum acceptable boot time in us.
MAX_BOOT_TIME_US = 150000
# TODO: Keep a `current` boot time in S3 and validate we don't regress
# Regex for obtaining boot time from some string.
TIMESTAMP_LOG_REGEX = r'Guest-boot-time\ \=\ (\d+)'


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
    Assert that we meet the minimum boot time. Should use a Microvm with the
    `boottime` capability.
    """

    microvm.basic_config(
        vcpu_count=2,
        mem_size_mib=1024
    )
    if net_config:
        _tap = microvm.ssh_network_config(net_config, '1')

    # Configure logging.
    log_fifo_path = os.path.join(microvm.slot.path, 'log_fifo')
    metrics_fifo_path = os.path.join(microvm.slot.path, 'metrics_fifo')
    assert log_tools.make_fifo(log_fifo_path)
    assert log_tools.make_fifo(metrics_fifo_path)

    response = microvm.logger.put(
        log_fifo=microvm.slot.jailer_context.jailed_path(
            log_fifo_path,
            create=True
        ),
        metrics_fifo=microvm.slot.jailer_context.jailed_path(
            metrics_fifo_path,
            create=True
        ),
        level='Warning',
        show_level=False,
        show_log_origin=False
    )
    assert microvm.api_session.is_good_response(response.status_code)

    microvm.start()
    time.sleep(0.4)
    lines = log_tools.sequential_fifo_reader(log_fifo_path, 20)

    boot_time_us = 0
    for line in lines:
        timestamps = re.findall(TIMESTAMP_LOG_REGEX, line)
        if timestamps:
            boot_time_us = int(timestamps[0])

    assert boot_time_us > 0
    assert boot_time_us < MAX_BOOT_TIME_US
    return boot_time_us
