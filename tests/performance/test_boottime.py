"""
Tests that ensure the boot time to init process is within spec.

# TODO

- Get the minimum acceptable boot time from the `spec.firecracker` s3 bucket.
  Also set the current boot time if we're running as part of a continuous
  integration merge operation.
"""

import os
import re
from subprocess import run
import time

import pytest


@pytest.mark.timeout(240)
def test_microvm_boottime(test_microvm_with_boottime):
    """
    Asserts that we meet the minimum boot time. Microvms with the boottimer
    capability should use a kernel config customized for quick booting within
    Firecracker.
    """

    MIN_BOOT_TIME = 0.35
    """ The minimum acceptable boot time. """
    # TODO: This needs to be 0.15, is currently ~0.3 (investigation ongoing).
    # TODO: Get the minimum acceptable boot time from the `spec.firecracker` s3
    #       bucket. Also set the current boot time if we're running as part of
    #       continuous integration merge operation.

    BOOTTIME_INIT_PROGRAM = 'test_boottime_init.c'
    """
    This program saves an accurate timestamp to disk and exists. It will be
    compiled statically and copied into the guest root file system as the init
    program.
    """

    TIMESTAMP_LOG_FILE = 'timestamp.log'
    """ The timestamp log file within the microvm root file system. """

    TIMESTAMP_LOG_REGEX = r'^\[(\d+\.\d+)\]\ init\ executed'
    """ Regex for extracting timestamp data from a the boot time log. """

    test_microvm = test_microvm_with_boottime
    test_microvm.basic_config()

    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/timer_rootfs',
        json={
            'drive_id': 'timer_rootfs',
            'path_on_host': test_microvm.slot.make_fsfile(name='timer_rootfs'),
            'is_root_device': True,
            'permissions': 'rw',
            'state': 'Attached'
        }
    )
    """ Create a new empty root file system and attach it. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    init_binary = test_microvm.slot.path + 'init'
    run(
        'gcc -static -O3 {boottime_init_program} -o {binary_path}'.format(
            binary_path=init_binary,
            boottime_init_program=(
                os.path.dirname(os.path.abspath(__file__)) + '/' +
                BOOTTIME_INIT_PROGRAM
            )
        ),
        shell=True,
        check=True
    )
    """ Compile the timer program as a binary named `init`. """

    test_microvm.slot.fsfiles['timer_rootfs'].copy_to(init_binary, 'sbin/')
    """ Copy the init program to the root file system. """

    response = test_microvm.api_session.put(
        test_microvm.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    """ Issues a power-on command to the microvm. """

    boot_start_time_realtime = time.clock_gettime(time.CLOCK_REALTIME)

    assert(test_microvm.api_session.is_good_response(response.status_code))

    """ Starts the boot timer. """

    time.sleep(1)
    response = test_microvm.api_session.get(
        test_microvm.actions_url + '/1'
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))

    try:
        test_microvm.slot.fsfiles['timer_rootfs'].copy_from(
            TIMESTAMP_LOG_FILE,
            test_microvm.slot.path
        )
        """ Retrieves the guest OS boot timestamp. """
    except:
        print("Could not get timestamp log (after 1 second).")
        raise
    """
    If the microvm doesn't boot and print a timestamp within 1 second, it's
    all in vain anyway ...
    """

    with open(test_microvm.slot.path + TIMESTAMP_LOG_FILE) as timestamp_log:
        timestamps = re.findall(TIMESTAMP_LOG_REGEX, timestamp_log.read())
        boot_end_time_realtime = float(timestamps[0])

    boot_time_realtime = boot_end_time_realtime - boot_start_time_realtime

    print("Boot time: " + str(round(boot_time_realtime * 1000)) + "ms")
    # Print this to the test session output until we have s3 upload.

    assert(boot_time_realtime < MIN_BOOT_TIME)
