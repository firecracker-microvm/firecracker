"""Tests the format of human readable logs by checking response of the API
config calls."""

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


def check_log_message(log_str, log_level, show_level, show_origin):
    """Parse the string representing the logs and look for the parts
     that should be there.
    """
    log_str_parts = log_str.split(' ')

    # The timestamp is the first part of the log message always.
    timestamp = log_str_parts[0][:-10]
    strptime(timestamp, "%Y-%m-%dT%H:%M:%S")

    if not show_level and not show_origin:
        # In case the log does not contain level or origin, log message has 2
        # parts and that is the least we are checking.
        assert log_str_parts[1] != "[]"
        assert len(log_str_parts) > 1
        return

    log_str_parts_info = log_str_parts[1][1:-1].split(':')
    # Make sure that the log contains at least two parts (timestamp,
    # info and log message) in case level or origin should be there.
    assert len(log_str_parts) > 2
    if show_level:
        index_configured_level = LOG_LEVELS.index(
                                    to_formal_log_level(log_level))
        index_logged_level = LOG_LEVELS.index(log_str_parts_info[0])
        assert index_logged_level <= index_configured_level

    if show_origin:
        if show_level:
            log_path = log_str_parts_info[1]
            log_line_number = log_str_parts_info[2]
        else:
            log_path = log_str_parts_info[0]
            log_line_number = log_str_parts_info[1]
        path_components = log_path.split('/')
        assert len(path_components) > 1
        assert int(log_line_number)


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
        check_log_message(line, log_level, show_level, show_origin)
