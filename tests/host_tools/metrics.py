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
import json
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

from aws_embedded_metrics.constants import DEFAULT_NAMESPACE
from aws_embedded_metrics.logger.metrics_logger_factory import create_metrics_logger


class MetricsWrapper:
    """A convenient metrics logger"""

    def __init__(self, logger):
        self.metrics = {}
        self.dimensions = {}
        self.logger = logger

    def set_dimensions(self, *dimensions, **kwargs):
        """Set dimensions"""
        if self.logger:
            self.logger.set_dimensions(*dimensions, **kwargs)

        self.dimensions = {}
        for dimension_dict in dimensions:
            for k, v in dimension_dict.items():
                self.dimensions[k] = v

    def put_metric(self, name, data, unit):
        """Put a datapoint with given dimensions"""
        if name not in self.metrics:
            self.metrics[name] = {"unit": unit, "values": []}
        self.metrics[name]["values"].append(data)

        if self.logger:
            self.logger.put_metric(name, data, unit)

    def set_property(self, *args, **kwargs):
        """Set a property"""
        if self.logger:
            self.logger.set_property(*args, **kwargs)

    def flush(self):
        """Flush any remaining metrics"""
        if self.logger:
            asyncio.run(self.logger.flush())

    def store_data(self, dir_path):
        """Store data into a file"""
        metrics_path = Path(dir_path / "metrics.json")
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "metrics": self.metrics,
                    "dimensions": self.dimensions,
                },
                f,
            )


def get_metrics_logger():
    """Get a new metrics logger object"""
    # if no metrics namespace, don't output metrics
    if "AWS_EMF_NAMESPACE" in os.environ:
        logger = create_metrics_logger()
        logger.reset_dimensions(False)
    else:
        logger = None
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
