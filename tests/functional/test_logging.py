"""Tests the format of human readable logs by checking response of the API
config calls."""

import re
from time import strptime
import host_tools.logging as log_tools

# Array of supported log levels of the current logging system.
# Do not change order of values inside this array as logic depends on this.
LOG_LEVELS = ["ERROR", "WARN", "INFO", "DEBUG"]


def to_formal_log_level(log_level):
    """
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
    """Parse the string representing the logs and look for the parts
     that should be there.
     The log line should look lie this:
         YYYY-MM-DDTHH:MM:SS.NNNNNNNNN [ID:LEVEL:FILE:LINE] MESSAGE
     where LEVEL and FILE:LINE are both optional.
     e.g.:
        2018-09-09T12:52:00.123456789 [MYID:WARN:/path/to/file.rs:52] warning
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


def test_no_origin_logs(test_microvm_with_ssh, network_config):
    """Check that logs do not contain the origin (i.e file and line number)."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        net_config=network_config,
        show_level=True,
        show_origin=False
    )


def test_no_level_logs(test_microvm_with_ssh, network_config):
    """Check that logs do not contain the level."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        net_config=network_config,
        show_level=False,
        show_origin=True
    )


def test_no_nada_logs(test_microvm_with_ssh, network_config):
    """Check that logs do not contain either level or origin."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        net_config=network_config,
        show_level=False,
        show_origin=False
    )


def test_info_logs(test_microvm_with_ssh, network_config):
    """Check output of logs when minimum level to be displayed is info."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        net_config=network_config,
    )


def test_warn_logs(test_microvm_with_ssh, network_config):
    """Check output of logs when minimum level to be displayed is warning."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        net_config=network_config,
        log_level='Warning'
    )


def test_error_logs(test_microvm_with_ssh, network_config):
    """Check output of logs when minimum level of logs displayed is error."""
    _test_log_config(
        microvm=test_microvm_with_ssh,
        net_config=network_config,
        log_level='Error'
    )


def _test_log_config(
        microvm,
        net_config,
        log_level='Info',
        show_level=True,
        show_origin=True
):
    """Exercises different scenarios for testing the logging config."""
    microvm.basic_config(net_iface_count=0, log_enable=False)
    microvm.basic_network_config(net_config)
    microvm.logger_config(log_level, show_level, show_origin)

    microvm.start()

    lines = log_tools.sequential_fifo_reader(microvm, 0, 20)
    for line in lines:
        check_log_message(
            line,
            microvm.slot.jailer_context.microvm_slot_id,
            log_level,
            show_level,
            show_origin
        )
