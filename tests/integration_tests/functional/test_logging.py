# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the format of human readable logs.

It checks the response of the API configuration calls and the logs that show
up in the configured logging FIFO.
"""
import os
import platform
import re

from time import strptime

import host_tools.logging as log_tools


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


def check_log_message(log_str, instance_id, level, show_level, show_origin):
    """Ensure correctness of the logged message.

    Parse the string representing the logs and look for the parts
    that should be there.
    The log line should look lie this:
         YYYY-MM-DDTHH:MM:SS.NNNNNNNNN [ID:LEVEL:FILE:LINE] MESSAGE
    where LEVEL and FILE:LINE are both optional.
    e.g.:
    `2018-09-09T12:52:00.123456789 [MYID:WARN:/path/to/file.rs:52] warning`
    """
    (timestamp, tag, _) = log_str.split(' ')[:3]
    timestamp = timestamp[:-10]
    strptime(timestamp, "%Y-%m-%dT%H:%M:%S")

    pattern = "\\[(" + instance_id + ")"
    if show_level:
        pattern += ":(" + "|".join(LOG_LEVELS) + ")"
    if show_origin:
        pattern += ":([^:]+/[^:]+):([0-9]+)"
    pattern += "\\]"

    mo = re.match(pattern, tag)
    assert mo is not None

    if show_level:
        tag_level = mo.group(2)
        tag_level_no = LOG_LEVELS.index(tag_level)
        configured_level_no = LOG_LEVELS.index(to_formal_log_level(level))
        assert tag_level_no <= configured_level_no


def test_no_origin_logs(test_microvm_with_ssh):
    """Check that logs do not contain the origin (i.e file and line number)."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        show_level=True,
        show_origin=False
    )


def test_no_level_logs(test_microvm_with_ssh):
    """Check that logs do not contain the level."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        show_level=False,
        show_origin=True
    )


def test_no_nada_logs(test_microvm_with_ssh):
    """Check that logs do not contain either level or origin."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        show_level=False,
        show_origin=False
    )


def test_info_logs(test_microvm_with_ssh):
    """Check output of logs when minimum level to be displayed is info."""
    _test_log_config(microvm=test_microvm_with_ssh)


def test_warn_logs(test_microvm_with_ssh):
    """Check output of logs when minimum level to be displayed is warning."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        log_level='Warning'
    )


def test_error_logs(test_microvm_with_ssh):
    """Check output of logs when minimum level of logs displayed is error."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        log_level='Error'
    )


def test_log_config_failure(test_microvm_with_api):
    """Check passing invalid FIFOs is detected and reported as an error."""
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()

    response = microvm.logger.put(
        log_path='invalid log fifo',
        level='Info',
        show_level=True,
        show_log_origin=True,
    )
    assert microvm.api_session.is_status_bad_request(response.status_code)
    assert response.json()['fault_message']


def log_file_contains_strings(log_fifo, string_list):
    """Check if the log fifo contains all strings in string_list.

    We search for each string in the string_list array only in the
    first 100 lines of the log.
    """
    log_lines = log_fifo.sequential_reader(100)
    for log_line in log_lines:
        for text in string_list:
            if text in log_line:
                string_list.remove(text)
                break
        if not string_list:
            return True

    return False


def test_api_requests_logs(test_microvm_with_api):
    """Test that API requests are logged."""
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()

    # Configure logging.
    log_fifo_path = os.path.join(microvm.path, 'log_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)

    response = microvm.logger.put(
        log_path=microvm.create_jailed_resource(log_fifo.path),
        level='Info',
        show_level=True,
        show_log_origin=True,
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    expected_log_strings = []

    # Check that a Patch request on /machine-config is logged.
    response = microvm.machine_cfg.patch(vcpu_count=4)
    assert microvm.api_session.is_status_no_content(response.status_code)
    # We are not interested in the actual body. Just check that the log
    # message also has the string "body" in it.
    expected_log_strings.append(
        "The API server received a Patch request "
        "on \"/machine-config\" with body"
    )

    # Check that a Put request on /machine-config is logged.
    response = microvm.machine_cfg.put(
        vcpu_count=4,
        ht_enabled=False,
        mem_size_mib=128
    )
    assert microvm.api_session.is_status_no_content(response.status_code)
    expected_log_strings.append(
        "The API server received a Put request "
        "on \"/machine-config\" with body"
    )

    # Check that a Get request on /machine-config is logged without the
    # body.
    response = microvm.machine_cfg.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    expected_log_strings.append(
        "The API server received a Get request "
        "on \"/machine-config\"."
    )

    # Check that all requests on /mmds are logged without the body.
    dummy_json = {
        'latest': {
            'meta-data': {
                'ami-id': 'dummy'
            }
        }
    }
    response = microvm.mmds.put(json=dummy_json)
    assert microvm.api_session.is_status_no_content(response.status_code)
    expected_log_strings.append(
        "The API server received a Put request on \"/mmds\"."
    )

    response = microvm.mmds.patch(json=dummy_json)
    assert microvm.api_session.is_status_no_content(response.status_code)
    expected_log_strings.append(
        "The API server received a Patch request on \"/mmds\"."
    )

    response = microvm.mmds.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    expected_log_strings.append(
        "The API server received a Get request on \"/mmds\"."
    )

    # Check that the fault message return by the client is also logged in the
    # FIFO.
    response = microvm.boot.put(
        kernel_image_path="inexistent_path"
    )
    assert microvm.api_session.is_status_bad_request(response.status_code)
    fault_message = "The kernel file cannot be opened: No such file or " \
                    "directory (os error 2)"
    assert fault_message in response.text
    expected_log_strings.append("Received Error. "
                                "Status code: 400 Bad Request. "
                                "Message: {}".format(fault_message))

    assert log_file_contains_strings(log_fifo, expected_log_strings)


# pylint: disable=W0102
def _test_log_config(
        microvm,
        log_level='Info',
        show_level=True,
        show_origin=True
):
    """Exercises different scenarios for testing the logging config."""
    microvm.spawn()

    microvm.basic_config()

    # Configure logging.
    log_fifo_path = os.path.join(microvm.path, 'log_fifo')
    log_fifo = log_tools.Fifo(log_fifo_path)
    if platform.machine() == 'x86_64':
        response = microvm.logger.put(
            log_path=microvm.create_jailed_resource(log_fifo.path),
            level=log_level,
            show_level=show_level,
            show_log_origin=show_origin
           )
    else:
        response = microvm.logger.put(
            log_path=microvm.create_jailed_resource(log_fifo.path),
            level=log_level,
            show_level=show_level,
            show_log_origin=show_origin,
           )

    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start()

    lines = log_fifo.sequential_reader(20)
    for idx, line in enumerate(lines):
        if idx == 0:
            assert line.startswith("Running Firecracker")
            continue
        check_log_message(
            line,
            microvm.id,
            log_level,
            show_level,
            show_origin
        )
