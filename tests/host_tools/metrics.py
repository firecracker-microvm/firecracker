# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixture to send metrics to AWS CloudWatch

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
import json
import os
import socket
from urllib.parse import urlparse

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

    emf_msg["_aws"]["LogGroupName"] = os.environ.get(
        "AWS_EMF_LOG_GROUP_NAME", f"{os.environ['AWS_EMF_NAMESPACE']}-metrics"
    )
    emf_msg["_aws"]["LogStreamName"] = ""

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
