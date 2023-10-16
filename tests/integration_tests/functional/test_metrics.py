# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

import datetime
import math
import platform


def _validate_metrics(metrics):
    """
    This functions makes sure that all components
    of FirecrackerMetrics struct are present.
    In depth validation of metrics for each component
    should be implemented in its own test.
    e.g. validation of NetDeviceMetrics should implement
    _validate_net_metrics() to check for breaking change etc.
    """
    exp_keys = [
        "utc_timestamp_ms",
        "api_server",
        "balloon",
        "block",
        "deprecated_api",
        "get_api_requests",
        "i8042",
        "latencies_us",
        "logger",
        "mmds",
        "net",
        "patch_api_requests",
        "put_api_requests",
        "seccomp",
        "vcpu",
        "vmm",
        "uart",
        "signals",
        "vsock",
        "entropy",
    ]

    if platform.machine() == "aarch64":
        exp_keys.append("rtc")

    assert set(exp_keys).issubset(metrics.keys())

    utc_time = datetime.datetime.now(datetime.timezone.utc)
    utc_timestamp_ms = math.floor(utc_time.timestamp() * 1000)

    # Assert that the absolute difference is less than 1 second, to check that
    # the reported utc_timestamp_ms is actually a UTC timestamp from the Unix
    # Epoch.Regression test for:
    # https://github.com/firecracker-microvm/firecracker/issues/2639
    assert abs(utc_timestamp_ms - metrics["utc_timestamp_ms"]) < 1000


class FcDeviceMetrics:
    """
    Provides functions to validate breaking change and
    aggregation of metrics
    """

    def __init__(self, name, validate_fn, num_dev):
        self.dev_name = name
        self.validate_dev_metrics = validate_fn
        self.num_dev = num_dev

    def validate(self, microvm):
        """
        validate breaking change of device metrics
        """
        fc_metrics = microvm.flush_metrics()

        # make sure all items of FirecrackerMetrics are as expected
        _validate_metrics(fc_metrics)

        # check for breaking change in device specific metrics
        self.validate_dev_metrics(fc_metrics[self.dev_name])

        # make sure "{self.name}" is aggregate of "{self.name}_*"
        # and that there are only {num_dev} entries of "{self.name}_*"
        self.validate_aggregation(fc_metrics)
        print(f"\nsuccessfully validated aggregate of {self.dev_name} metrics")

    def validate_aggregation(self, fc_metrics):
        """
        validate aggregation of device metrics
        """
        metrics_aggregate = fc_metrics[self.dev_name]
        metrics_calculated = {}
        actual_num_devices = 0
        print(f"In aggregation of {self.dev_name} expected {self.num_dev=}")
        for component_metric_names, component_metric_values in fc_metrics.items():
            if f"{self.dev_name}_" in component_metric_names:
                print(f"found {component_metric_names} during aggr of {self.dev_name}")
                actual_num_devices += 1
                for metrics_name, metric_value in component_metric_values.items():
                    if metrics_name not in metrics_calculated:
                        metrics_calculated[metrics_name] = 0
                    metrics_calculated[metrics_name] += metric_value
        assert metrics_aggregate == metrics_calculated
        assert self.num_dev == actual_num_devices


def test_flush_metrics(test_microvm_with_api):
    """
    Check the `FlushMetrics` vmm action.
    """
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()
    microvm.start()

    metrics = microvm.flush_metrics()
    _validate_metrics(metrics)


def _validate_net_metrics(net_metrics):
    exp_keys = [
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
    ]
    assert set(net_metrics.keys()) == set(exp_keys)


def test_net_metrics(test_microvm_with_api):
    """
    Validate that NetDeviceMetrics doesn't have a breaking change
    and "net" is aggregate of all "net_*" in the json object.
    """
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # randomly selected 10 as the number of net devices to test
    num_net_devices = 10

    net_metrics = FcDeviceMetrics("net", _validate_net_metrics, num_net_devices)

    # create more than 1 net devices to test aggregation
    for _ in range(num_net_devices):
        test_microvm.add_net_iface()
    test_microvm.start()

    # check that the started microvm has "net" and "NUM_NET_DEVICES" number of "net_" metrics
    net_metrics.validate(test_microvm)

    for i in range(num_net_devices):
        # Test that network devices attached are operational.
        # Verify if guest can run commands.
        exit_code, _, _ = test_microvm.ssh_iface(i).run("sync")
        # test that we get metrics while interacting with different interfaces
        net_metrics.validate(test_microvm)
        assert exit_code == 0
