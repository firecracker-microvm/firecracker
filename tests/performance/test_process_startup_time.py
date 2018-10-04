"""
Tests that ensure the process startup time up to socket bind is within spec.
"""

import json
import time
import pytest
import host_tools.logging as log_tools

MAX_STARTUP_TIME_US = 80
""" The maximum acceptable startup time in ms. """
# TODO: Keep a `current` startup time in S3 and validate we don't regress


@pytest.mark.timeout(100)
def test_startup_time(test_microvm_with_api):
    """Check the startup time for jailer and Firecracker up to socket bind."""

    microvm = test_microvm_with_api
    microvm.basic_config(
        vcpu_count=2,
        mem_size_mib=1024,
        net_iface_count=0,
        log_enable=True
    )

    microvm.start()
    time.sleep(0.4)

    # The metrics fifo should be at index 1.
    # Since metrics are flushed at InstanceStart, the first line will suffice.
    lines = log_tools.sequential_fifo_reader(microvm, 1, 1)
    metrics = json.loads(lines[0])
    startup_time = int(metrics['api_server']['process_startup_time_ms'])

    print('Process startup time is: {} ms'.format(startup_time))

    assert startup_time > 0
    assert startup_time <= MAX_STARTUP_TIME_US
