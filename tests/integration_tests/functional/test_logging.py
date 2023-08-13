# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the format of human readable logs.

It checks the response of the API configuration calls and the logs that show
up in the configured logging FIFO.
"""

import datetime
import os

import host_tools.logging as log_tools


def level_int(level):
    """Converts a log level string to an integer representation"""

    if level == "ERROR":
        return 0
    if level == "WARN":
        return 1
    if level == "INFO":
        return 2
    if level == "DEBUG":
        return 3
    if level == "TRACE":
        return 4
    raise Exception("Invalid level")


# pylint: disable=anomalous-backslash-in-string
def check_log_message_format(log_str, log_level, show_level, show_origin):
    """Ensure correctness of the logged message.

    Parse the string representing the logs and look for the parts
    that should be there.
    The log line should look like:
    > {year}-{month}-{day}T{hour}:{minute}:{second}.{microsecond}Z {level} {thread name}
    > {process name}: {file}:{line number} {message}
    where `level`, `file` and `line number` are optional e.g.
    > 2023-07-19T12:10:54.608814Z  INFO main test_bin_3: src\main.rs:18: yak shaving completed.
    """
    split = iter(log_str.split())
    now = datetime.datetime.now()

    timestamp = next(split)
    date, time = timestamp.split("T")
    year, month, day = date.split("-")
    assert len(month) == 2
    assert len(day) == 2

    assert time[-1] == "Z"
    hour, minute, secs = time[:-1].split(":")
    second, microsecond = secs.split(".")
    assert len(hour) == 2
    assert len(minute) == 2
    assert len(second) == 2
    assert len(microsecond) == 6

    # Assert the time in the logs is less than or equal to the current time
    log_time = datetime.datetime(
        year=int(year),
        month=int(month),
        day=int(day),
        hour=int(hour),
        minute=int(minute),
        second=int(second),
        microsecond=int(microsecond),
    )
    assert log_time <= now

    if show_level:
        level = next(split)
        assert level in ("ERROR", "WARN", "INFO", "DEBUG", "TRACE")
        assert level_int(level) <= level_int(log_level.upper())

    # Thread names are not optional.
    _thread_name = next(split)
    # Process names are not optional.
    _process_name = next(split)

    if show_origin:
        origin = next(split)
        assert origin[-1] == ":"
        _path, line = origin[:-1].split(":")
        assert line.isnumeric()


def test_no_origin_logs(test_microvm_with_api):
    """
    Check that logs do not contain the origin (i.e file and line number).
    """
    _test_log_config(microvm=test_microvm_with_api, show_level=True, show_origin=False)


def test_no_level_logs(test_microvm_with_api):
    """
    Check that logs do not contain the level.
    """
    _test_log_config(microvm=test_microvm_with_api, show_level=False, show_origin=True)


def test_no_nada_logs(test_microvm_with_api):
    """
    Check that logs do not contain either level or origin.
    """
    _test_log_config(microvm=test_microvm_with_api, show_level=False, show_origin=False)


def test_info_logs(test_microvm_with_api):
    """
    Check output of logs when minimum level to be displayed is info.
    """
    _test_log_config(microvm=test_microvm_with_api)


def test_warn_logs(test_microvm_with_api):
    """
    Check output of logs when minimum level to be displayed is warning.
    """
    _test_log_config(microvm=test_microvm_with_api, log_level="Warn")


def test_error_logs(test_microvm_with_api):
    """
    Check output of logs when minimum level of logs displayed is error.
    """
    _test_log_config(microvm=test_microvm_with_api, log_level="Error")


def test_log_config_failure(test_microvm_with_api):
    """
    Check passing invalid FIFOs is detected and reported as an error.
    """
    microvm = test_microvm_with_api
    microvm.spawn(create_logger=False)
    microvm.basic_config()

    response = microvm.logger.put(
        log_path="invalid log fifo",
        level="Info",
        show_level=True,
        show_log_origin=True,
    )
    # only works if log level is Debug
    microvm.time_api_requests = False
    assert microvm.api_session.is_status_bad_request(response.status_code)
    assert response.json()["fault_message"]


def test_api_requests_logs(test_microvm_with_api):
    """
    Test that API requests are logged.
    """
    microvm = test_microvm_with_api
    microvm.spawn(create_logger=False)
    microvm.basic_config()

    # Configure logging.
    log_fifo_path = os.path.join(microvm.path, "log_fifo")
    log_fifo = log_tools.Fifo(log_fifo_path)

    response = microvm.logger.put(
        log_path=microvm.create_jailed_resource(log_fifo.path),
        level="Info",
        show_level=True,
        show_log_origin=True,
    )
    # only works if log level is Debug
    microvm.time_api_requests = False
    assert microvm.api_session.is_status_no_content(response.status_code)
    microvm.start_console_logger(log_fifo)

    # Check that a Patch request on /machine-config is logged.
    response = microvm.machine_cfg.patch(vcpu_count=4)
    assert microvm.api_session.is_status_no_content(response.status_code)
    # We are not interested in the actual body. Just check that the log
    # message also has the string "body" in it.
    microvm.check_log_message(
        "The API server received a Patch request " 'on "/machine-config" with body'
    )

    # Check that a Put request on /machine-config is logged.
    response = microvm.machine_cfg.put(vcpu_count=4, mem_size_mib=128)
    assert microvm.api_session.is_status_no_content(response.status_code)
    microvm.check_log_message(
        "The API server received a Put request " 'on "/machine-config" with body'
    )

    # Check that a Get request on /machine-config is logged without the
    # body.
    response = microvm.machine_cfg.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    microvm.check_log_message(
        "The API server received a Get request " 'on "/machine-config".'
    )

    # Check that all requests on /mmds are logged without the body.
    dummy_json = {"latest": {"meta-data": {"ami-id": "dummy"}}}
    response = microvm.mmds.put(json=dummy_json)
    assert microvm.api_session.is_status_no_content(response.status_code)
    microvm.check_log_message('The API server received a Put request on "/mmds".')

    response = microvm.mmds.patch(json=dummy_json)
    assert microvm.api_session.is_status_no_content(response.status_code)
    microvm.check_log_message('The API server received a Patch request on "/mmds".')

    response = microvm.mmds.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    microvm.check_log_message('The API server received a Get request on "/mmds".')

    # Check that the fault message return by the client is also logged in the
    # FIFO.
    response = microvm.boot.put(kernel_image_path="inexistent_path")
    assert microvm.api_session.is_status_bad_request(response.status_code)
    fault_message = (
        "The kernel file cannot be opened: No such file or " "directory (os error 2)"
    )
    assert fault_message in response.text
    microvm.check_log_message(
        "Received Error. "
        "Status code: 400 Bad Request. "
        "Message: {}".format(fault_message)
    )


# pylint: disable=W0102
def _test_log_config(microvm, log_level="Info", show_level=True, show_origin=True):
    """Exercises different scenarios for testing the logging config."""
    microvm.spawn(create_logger=False)
    # only works if log level is Debug
    microvm.time_api_requests = False

    # Configure logging.
    log_fifo_path = os.path.join(microvm.path, "log_fifo")
    log_fifo = log_tools.Fifo(log_fifo_path)
    response = microvm.logger.put(
        log_path=microvm.create_jailed_resource(log_fifo.path),
        level=log_level,
        show_level=show_level,
        show_log_origin=show_origin,
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    microvm.start_console_logger(log_fifo)

    microvm.basic_config()
    microvm.start()

    lines = microvm.log_data.splitlines()
    for line in lines:
        check_log_message_format(line, log_level, show_level, show_origin)
