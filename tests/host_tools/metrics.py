# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixture to send metrics to AWS CloudWatch and validate Firecracker metrics

We use the aws-embedded-metrics library although it has some sharp corners,
namely:

1. It uses asyncio, which complicates the flushing a bit.

2. It has an stateful API. Setting dimensions will override previous ones.

Example:

    set_dimensions("instance")
    put_metric("duration", 1)
    set_dimensions("cpu")
    put_metric("duration", 1)

This will end with 2 identical metrics with dimension "cpu" (the last one). The
correct way of doing it is:

    set_dimensions("instance")
    put_metric("duration", 1)
    flush()
    set_dimensions("cpu")
    put_metric("duration", 1)

This is not very intuitive, but we assume all metrics within a test will have
the same dimensions.

# Debugging

You can override the destination of the metrics to stdout with:

    AWS_EMF_NAMESPACE=$USER-test
    AWS_EMF_ENVIRONMENT=local ./tools/devtest test

# References:

- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
- https://github.com/awslabs/aws-embedded-metrics-python
"""

import asyncio
import datetime
import json
import math
import os
import platform
import socket
from urllib.parse import urlparse

import jsonschema
from aws_embedded_metrics.constants import DEFAULT_NAMESPACE
from aws_embedded_metrics.logger.metrics_logger_factory import create_metrics_logger


class MetricsWrapperDummy:
    """Send metrics to /dev/null"""

    def set_dimensions(self, *args, **kwargs):
        """Set dimensions"""

    def put_metric(self, *args, **kwargs):
        """Put a datapoint with given dimensions"""

    def set_property(self, *args, **kwargs):
        """Set a property"""

    def flush(self):
        """Flush any remaining metrics"""


class MetricsWrapper:
    """A convenient metrics logger"""

    def __init__(self, logger):
        self.logger = logger

    def __getattr__(self, attr):
        """Dispatch methods to logger instance"""
        if attr not in self.__dict__:
            return getattr(self.logger, attr)
        return getattr(self, attr)

    def flush(self):
        """Flush any remaining metrics"""
        asyncio.run(self.logger.flush())


def get_metrics_logger():
    """Get a new metrics logger object"""
    # if no metrics namespace, don't output metrics
    if "AWS_EMF_NAMESPACE" not in os.environ:
        return MetricsWrapperDummy()
    logger = create_metrics_logger()
    logger.reset_dimensions(False)
    return MetricsWrapper(logger)


def emit_raw_emf(emf_msg: dict):
    """Emites a raw EMF log message to the local cloudwatch agent"""
    if "AWS_EMF_AGENT_ENDPOINT" not in os.environ:
        return

    namespace = os.environ.get("AWS_EMF_NAMESPACE", DEFAULT_NAMESPACE)
    emf_msg["_aws"]["LogGroupName"] = os.environ.get(
        "AWS_EMF_LOG_GROUP_NAME", f"{namespace}-metrics"
    )
    emf_msg["_aws"]["LogStreamName"] = os.environ.get("AWS_EMF_LOG_STREAM_NAME", "")
    for metrics in emf_msg["_aws"]["CloudWatchMetrics"]:
        metrics["Namespace"] = namespace

    emf_endpoint = urlparse(os.environ["AWS_EMF_AGENT_ENDPOINT"])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(
            (json.dumps(emf_msg) + "\n").encode("utf-8"),
            (emf_endpoint.hostname, emf_endpoint.port),
        )


UNIT_REDUCTIONS = {
    "Microseconds": "Milliseconds",
    "Milliseconds": "Seconds",
    "Bytes": "Kilobytes",
    "Kilobytes": "Megabytes",
    "Megabytes": "Gigabytes",
    "Gigabytes": "Terabytes",
    "Bits": "Kilobits",
    "Kilobits": "Megabits",
    "Megabits": "Gigabits",
    "Gigabits": "Terabit",
    "Bytes/Second": "Kilobytes/Second",
    "Kilobytes/Second": "Megabytes/Second",
    "Megabytes/Second": "Gigabytes/Second",
    "Gigabytes/Second": "Terabytes/Second",
    "Bits/Second": "Kilobits/Second",
    "Kilobits/Second": "Megabits/Second",
    "Megabits/Second": "Gigabits/Second",
    "Gigabits/Second": "Terabits/Second",
}
INV_UNIT_REDUCTIONS = {v: k for k, v in UNIT_REDUCTIONS.items()}


UNIT_SHORTHANDS = {
    "Seconds": "s",
    "Microseconds": "μs",
    "Milliseconds": "ms",
    "Bytes": "B",
    "Kilobytes": "KB",
    "Megabytes": "MB",
    "Gigabytes": "GB",
    "Terabytes": "TB",
    "Bits": "Bit",
    "Kilobits": "KBit",
    "Megabits": "MBit",
    "Gigabits": "GBit",
    "Terabits": "TBit",
    "Percent": "%",
    "Count": "",
    "Bytes/Second": "B/s",
    "Kilobytes/Second": "KB/s",
    "Megabytes/Second": "MB/s",
    "Gigabytes/Second": "GB/s",
    "Terabytes/Second": "TB/s",
    "Bits/Second": "Bit/s",
    "Kilobits/Second": "KBit/s",
    "Megabits/Second": "MBit/s",
    "Gigabits/Second": "GBit/s",
    "Terabits/Second": "TBit/s",
    "Count/Second": "Hz",
    "None": "",
}


def reduce_value(value, unit):
    """
    Utility function for expressing a value in the largest possible unit in which it would still be >= 1

    For example, `reduce_value(1_000_000, Bytes)` would return (1, Megabytes)
    """
    # Could do this recursively, but I am worried about infinite recursion
    # due to precision problems (e.g. infinite loop of dividing/multiplying by 1000, alternating
    # between values < 1 and >= 1000).
    while abs(value) < 1 and unit in INV_UNIT_REDUCTIONS:
        value *= 1000
        unit = INV_UNIT_REDUCTIONS[unit]
    while abs(value) >= 1000 and unit in UNIT_REDUCTIONS:
        value /= 1000
        unit = UNIT_REDUCTIONS[unit]

    return value, unit


def format_with_reduced_unit(value, unit):
    """
    Utility function for pretty printing a given value by choosing a unit as large as possible,
    and then outputting its shorthand.

    For example, `format_with_reduced_unit(1_000_000, Bytes)` would return "1MB".
    """
    reduced_value, reduced_unit = reduce_value(value, unit)
    formatted_unit = UNIT_SHORTHANDS.get(reduced_unit, reduced_unit)

    return f"{reduced_value:.2f}{formatted_unit}"


def validate_fc_metrics(metrics):
    """
    This functions makes sure that all components
    of firecracker_metrics struct are present.
    """

    firecracker_metrics = {
        "api_server": [
            "process_startup_time_us",
            "process_startup_time_cpu_us",
            "sync_response_fails",
            "sync_vmm_send_timeout_count",
        ],
        "balloon": [
            "activate_fails",
            "inflate_count",
            "stats_updates_count",
            "stats_update_fails",
            "deflate_count",
            "event_fails",
        ],
        "block": [
            "activate_fails",
            "cfg_fails",
            "no_avail_buffer",
            "event_fails",
            "execute_fails",
            "invalid_reqs_count",
            "flush_count",
            "queue_event_count",
            "rate_limiter_event_count",
            "update_count",
            "update_fails",
            "read_bytes",
            "write_bytes",
            "read_count",
            "write_count",
            "rate_limiter_throttled_events",
            "io_engine_throttled_events",
        ],
        "deprecated_api": [
            "deprecated_http_api_calls",
            "deprecated_cmd_line_api_calls",
        ],
        "get_api_requests": [
            "instance_info_count",
            "machine_cfg_count",
            "mmds_count",
            "vmm_version_count",
        ],
        "i8042": [
            "error_count",
            "missed_read_count",
            "missed_write_count",
            "read_count",
            "reset_count",
            "write_count",
        ],
        "latencies_us": [
            "full_create_snapshot",
            "diff_create_snapshot",
            "load_snapshot",
            "pause_vm",
            "resume_vm",
            "vmm_full_create_snapshot",
            "vmm_diff_create_snapshot",
            "vmm_load_snapshot",
            "vmm_pause_vm",
            "vmm_resume_vm",
        ],
        "logger": [
            "missed_metrics_count",
            "metrics_fails",
            "missed_log_count",
            "log_fails",
        ],
        "mmds": [
            "rx_accepted",
            "rx_accepted_err",
            "rx_accepted_unusual",
            "rx_bad_eth",
            "rx_count",
            "tx_bytes",
            "tx_count",
            "tx_errors",
            "tx_frames",
            "connections_created",
            "connections_destroyed",
        ],
        "net": [
            "activate_fails",
            "cfg_fails",
            "mac_address_updates",
            "no_rx_avail_buffer",
            "no_tx_avail_buffer",
            "event_fails",
            "rx_queue_event_count",
            "rx_event_rate_limiter_count",
            "rx_partial_writes",
            "rx_rate_limiter_throttled",
            "rx_tap_event_count",
            "rx_bytes_count",
            "rx_packets_count",
            "rx_fails",
            "rx_count",
            "tap_read_fails",
            "tap_write_fails",
            "tx_bytes_count",
            "tx_malformed_frames",
            "tx_fails",
            "tx_count",
            "tx_packets_count",
            "tx_partial_reads",
            "tx_queue_event_count",
            "tx_rate_limiter_event_count",
            "tx_rate_limiter_throttled",
            "tx_spoofed_mac_count",
        ],
        "patch_api_requests": [
            "drive_count",
            "drive_fails",
            "network_count",
            "network_fails",
            "machine_cfg_count",
            "machine_cfg_fails",
            "mmds_count",
            "mmds_fails",
        ],
        "put_api_requests": [
            "actions_count",
            "actions_fails",
            "boot_source_count",
            "boot_source_fails",
            "drive_count",
            "drive_fails",
            "logger_count",
            "logger_fails",
            "machine_cfg_count",
            "machine_cfg_fails",
            "cpu_cfg_count",
            "cpu_cfg_fails",
            "metrics_count",
            "metrics_fails",
            "network_count",
            "network_fails",
            "mmds_count",
            "mmds_fails",
            "vsock_count",
            "vsock_fails",
        ],
        "seccomp": [
            "num_faults",
        ],
        "vcpu": [
            "exit_io_in",
            "exit_io_out",
            "exit_mmio_read",
            "exit_mmio_write",
            "failures",
        ],
        "vmm": [
            "device_events",
            "panic_count",
        ],
        "uart": [
            "error_count",
            "flush_count",
            "missed_read_count",
            "missed_write_count",
            "read_count",
            "write_count",
        ],
        "signals": [
            "sigbus",
            "sigsegv",
            "sigxfsz",
            "sigxcpu",
            "sigpipe",
            "sighup",
            "sigill",
        ],
        "vsock": [
            "activate_fails",
            "cfg_fails",
            "rx_queue_event_fails",
            "tx_queue_event_fails",
            "ev_queue_event_fails",
            "muxer_event_fails",
            "conn_event_fails",
            "rx_queue_event_count",
            "tx_queue_event_count",
            "rx_bytes_count",
            "tx_bytes_count",
            "rx_packets_count",
            "tx_packets_count",
            "conns_added",
            "conns_killed",
            "conns_removed",
            "killq_resync",
            "tx_flush_fails",
            "tx_write_fails",
            "rx_read_fails",
        ],
        "entropy": [
            "activate_fails",
            "entropy_event_fails",
            "entropy_event_count",
            "entropy_bytes",
            "host_rng_fails",
            "entropy_rate_limiter_throttled",
            "rate_limiter_event_count",
        ],
    }

    # validate timestamp before jsonschema validation which some more time
    utc_time = datetime.datetime.now(datetime.timezone.utc)
    utc_timestamp_ms = math.floor(utc_time.timestamp() * 1000)

    # Assert that the absolute difference is less than 1 second, to check that
    # the reported utc_timestamp_ms is actually a UTC timestamp from the Unix
    # Epoch.Regression test for:
    # https://github.com/firecracker-microvm/firecracker/issues/2639
    assert abs(utc_timestamp_ms - metrics["utc_timestamp_ms"]) < 1000

    if platform.machine() == "aarch64":
        firecracker_metrics["rtc"] = [
            "error_count",
            "missed_read_count",
            "missed_write_count",
        ]

    # add vhost-user metrics to the schema if applicable
    vhost_user_devices = []
    for metrics_name in metrics.keys():
        if metrics_name.startswith("vhost_user_"):
            firecracker_metrics[metrics_name] = [
                "activate_fails",
                "cfg_fails",
                "init_time_us",
                "activate_time_us",
                "config_change_time_us",
            ]
            vhost_user_devices.append(metrics_name)

    firecracker_metrics_schema = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    for metrics_name, metrics_fields in firecracker_metrics.items():
        metrics_schema = {
            "type": "object",
            "required": metrics_fields,
            "properties": {},
        }
        for metrics_field in metrics_fields:
            metrics_schema["properties"][metrics_field] = {"type": "number"}
        firecracker_metrics_schema["properties"][metrics_name] = metrics_schema
        firecracker_metrics_schema["required"].append(metrics_name)

    jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)

    def validate_missing_metrics(metrics):
        # remove some metrics and confirm that fields and not just top level metrics
        # are validated.
        temp_pop_metrics = metrics["api_server"].pop("process_startup_time_us")
        try:
            jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
        except jsonschema.exceptions.ValidationError as error:
            if (
                error.message.strip()
                == "'process_startup_time_us' is a required property"
            ):
                pass
            else:
                raise error
        metrics["api_server"]["process_startup_time_us"] = temp_pop_metrics

        if platform.machine() == "aarch64":
            temp_pop_metrics = metrics["rtc"].pop("error_count")
            try:
                jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
            except jsonschema.exceptions.ValidationError as error:
                if error.message.strip() == "'error_count' is a required property":
                    pass
                else:
                    raise error
            metrics["rtc"]["error_count"] = temp_pop_metrics

        for vhost_user_dev in vhost_user_devices:
            temp_pop_metrics = metrics[vhost_user_dev].pop("activate_time_us")
            try:
                jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
            except jsonschema.exceptions.ValidationError as error:
                if error.message.strip() == "'activate_time_us' is a required property":
                    pass
                else:
                    raise error
            metrics[vhost_user_dev]["activate_time_us"] = temp_pop_metrics

    validate_missing_metrics(metrics)


class FcDeviceMetrics:
    """
    Provides functions to validate breaking change and
    aggregation of metrics
    """

    def __init__(self, name, num_dev, aggr_supported=True):
        self.dev_name = name
        self.num_dev = num_dev
        self.aggr_supported = aggr_supported

    def validate(self, microvm):
        """
        validate breaking change of device metrics
        """
        fc_metrics = microvm.flush_metrics()

        # make sure all items of firecracker_metrics are as expected
        validate_fc_metrics(fc_metrics)

        # make sure "{self.name}" is aggregate of "{self.name}_*"
        # and that there are only {num_dev} entries of "{self.name}_*"
        self.validate_per_device_metrics(fc_metrics)

    def validate_per_device_metrics(self, fc_metrics):
        """
        validate aggregation of device metrics
        """
        metrics_calculated = {}
        actual_num_devices = 0
        for component_metric_names, component_metric_values in fc_metrics.items():
            if (
                f"{self.dev_name}_" in component_metric_names
                and component_metric_names.startswith(self.dev_name)
            ):
                actual_num_devices += 1
                for metrics_name, metric_value in component_metric_values.items():
                    if metrics_name not in metrics_calculated:
                        metrics_calculated[metrics_name] = 0
                    metrics_calculated[metrics_name] += metric_value

        assert self.num_dev == actual_num_devices
        if self.aggr_supported:
            metrics_aggregate = fc_metrics[self.dev_name]
            assert metrics_aggregate == metrics_calculated
