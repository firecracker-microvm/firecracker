# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

import datetime
import math
import platform

import jsonschema

FirecrackerMetrics = {
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


def _validate_metrics(metrics):
    """
    This functions makes sure that all components
    of FirecrackerMetrics struct are present.
    """

    if platform.machine() == "aarch64":
        FirecrackerMetrics["rtc"] = [
            "error_count",
            "missed_read_count",
            "missed_write_count",
        ]

    firecracker_metrics_schema = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    for metrics_name, metrics_fields in FirecrackerMetrics.items():
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

    # remove some metrics and confirm that fields and not just top level metrics
    # are validated.
    temp_pop_metrics = metrics["api_server"].pop("process_startup_time_us")
    try:
        jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
    except jsonschema.exceptions.ValidationError as error:
        if error.message.strip() == "'process_startup_time_us' is a required property":
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

    def __init__(self, name, num_dev):
        self.dev_name = name
        self.num_dev = num_dev

    def validate(self, microvm):
        """
        validate breaking change of device metrics
        """
        fc_metrics = microvm.flush_metrics()

        # make sure all items of FirecrackerMetrics are as expected
        _validate_metrics(fc_metrics)

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

    net_metrics = FcDeviceMetrics("net", num_net_devices)

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
