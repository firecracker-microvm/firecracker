# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the format of human readable logs.

It checks the response of the API configuration calls and the logs that show
up in the configured logging file.
"""

import re
from pathlib import Path
from time import strptime

import pytest

# Array of supported log levels of the current logging system.
# Do not change order of values inside this array as logic depends on this.
LOG_LEVELS = ["ERROR", "WARN", "INFO", "DEBUG"]


def to_formal_log_level(log_level):
    """Convert a pretty-print log level into the related log level code.

    Turns a pretty formatted log level (i.e Warning) into the one actually
    being logged (i.e WARN).
    :param log_level: pretty formatted log level
    :return: actual level being logged
    """
    if log_level == "Error":
        return LOG_LEVELS[0]
    if log_level == "Warning":
        return LOG_LEVELS[1]
    if log_level == "Info":
        return LOG_LEVELS[2]
    if log_level == "Debug":
        return LOG_LEVELS[3]
    return ""


def check_log_message_format(log_str, instance_id, level, show_level, show_origin):
    """Ensure correctness of the logged message.

    Parse the string representing the logs and look for the parts
    that should be there.
    The log line should look lie this:
         YYYY-MM-DDTHH:MM:SS.NNNNNNNNN [ID:THREAD:LEVEL:FILE:LINE] MESSAGE
    where LEVEL and FILE:LINE are both optional.
    e.g. with THREAD NAME as TN
    `2018-09-09T12:52:00.123456789 [MYID:TN:WARN:/path/to/file.rs:52] warning`
    """
    timestamp, tag_and_msg = log_str.split(" ", maxsplit=1)
    timestamp = timestamp[:-10]
    strptime(timestamp, "%Y-%m-%dT%H:%M:%S")

    pattern = "\\[(" + instance_id + ")"
    pattern += ":(.*)"
    if show_level:
        pattern += ":(" + "|".join(LOG_LEVELS) + ")"
    if show_origin:
        pattern += ":([^:]+/[^:]+):([0-9]+)"
    pattern += "\\].*"

    mo = re.match(pattern, tag_and_msg)
    assert (
        mo is not None
    ), f"Log message ({tag_and_msg}) does not match pattern ({pattern})."

    if show_level:
        tag_level = mo.group(3)
        tag_level_no = LOG_LEVELS.index(tag_level)
        configured_level_no = LOG_LEVELS.index(to_formal_log_level(level))
        assert tag_level_no <= configured_level_no


def test_log_config_failure(uvm_plain):
    """
    Check passing invalid FIFOs is detected and reported as an error.
    """
    microvm = uvm_plain
    microvm.spawn(log_file=None)
    microvm.basic_config()

    # only works if log level is Debug
    microvm.time_api_requests = False

    expected_msg = re.escape("No such file or directory (os error 2)")
    with pytest.raises(RuntimeError, match=expected_msg):
        microvm.api.logger.put(
            log_path="invalid log file",
            level="Info",
            show_level=True,
            show_log_origin=True,
        )


def test_api_requests_logs(uvm_plain):
    """
    Test that API requests are logged.
    """
    microvm = uvm_plain
    microvm.spawn(log_file=None)
    microvm.basic_config()

    # Configure logging.
    log_path = Path(microvm.path) / "log"
    log_path.touch()
    microvm.api.logger.put(
        log_path=microvm.create_jailed_resource(log_path),
        level="Info",
        show_level=True,
        show_log_origin=True,
    )
    microvm.log_file = log_path
    # only works if log level is Debug
    microvm.time_api_requests = False

    # Check that a Patch request on /machine-config is logged.
    microvm.api.machine_config.patch(vcpu_count=4)
    # We are not interested in the actual body. Just check that the log
    # message also has the string "body" in it.
    microvm.check_log_message(
        "The API server received a Patch request " 'on "/machine-config" with body'
    )

    # Check that a Put request on /machine-config is logged.
    microvm.api.machine_config.put(vcpu_count=4, mem_size_mib=128)
    microvm.check_log_message(
        "The API server received a Put request " 'on "/machine-config" with body'
    )

    # Check that a Get request on /machine-config is logged without the
    # body.
    microvm.api.machine_config.get()
    microvm.check_log_message(
        "The API server received a Get request " 'on "/machine-config".'
    )

    # Re-configure logging.
    log_path = Path(microvm.path) / "new_log"
    log_path.touch()
    microvm.api.logger.put(
        log_path=microvm.create_jailed_resource(log_path),
        level="Info",
        show_level=True,
        show_log_origin=True,
    )
    microvm.log_file = log_path

    # Check that all requests on /mmds are logged without the body.
    dummy_json = {"latest": {"meta-data": {"ami-id": "dummy"}}}
    microvm.api.mmds.put(json=dummy_json)
    microvm.check_log_message('The API server received a Put request on "/mmds".')

    microvm.api.mmds.patch(json=dummy_json)
    microvm.check_log_message('The API server received a Patch request on "/mmds".')

    microvm.api.mmds.get()
    microvm.check_log_message('The API server received a Get request on "/mmds".')

    # Check that the fault message return by the client is also logged in the
    # FIFO.
    fault_msg = "Boot source error: The kernel file cannot be opened: No such file or directory (os error 2)"
    with pytest.raises(RuntimeError, match=re.escape(fault_msg)):
        microvm.api.boot.put(kernel_image_path="inexistent_path")
    microvm.check_log_message(
        "Received Error. "
        "Status code: 400 Bad Request. "
        "Message: {}".format(fault_msg)
    )


@pytest.mark.parametrize(
    "log_level,show_level,show_origin",
    [
        ("Info", True, True),
        ("Info", False, True),
        ("Info", True, False),
        ("Info", False, False),
        ("Error", False, False),
        ("Warning", False, False),
    ],
)
def test_log_config(uvm_plain, log_level, show_level, show_origin):
    """Exercises different scenarios for testing the logging config."""
    microvm = uvm_plain
    microvm.spawn(
        log_level=log_level, log_show_level=show_level, log_show_origin=show_origin
    )
    microvm.basic_config()
    microvm.start()
    lines = microvm.log_data.splitlines()

    # Check for `Running Firecracker` message.
    configured_level_no = LOG_LEVELS.index(to_formal_log_level(log_level))
    info_level_no = LOG_LEVELS.index("INFO")
    if info_level_no <= configured_level_no:
        assert "Running Firecracker" in lines[0]

    # Check format of messages
    for line in lines:
        check_log_message_format(line, microvm.id, log_level, show_level, show_origin)
