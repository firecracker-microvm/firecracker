# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


"""Provides:
    - Mechanism to collect and export Firecracker metrics every 60seconds to CloudWatch
    - Utility functions to validate Firecracker metrics format and to validate Firecracker device metrics.
"""

import datetime
import math
import platform
import time
from threading import Thread

import jsonschema
import pytest

from framework.properties import global_props
from host_tools.metrics import get_metrics_logger


def create_metrics_schema_objects(metrics):
    """
    Helper functions to create jsonschema objects for
    Firecracker metrics.
    """
    metrics_schema = {
        "type": "object",
        "required": [],
        "properties": {},
        "additionalProperties": False,
    }

    if isinstance(metrics, dict):
        special_metrics = "utc_timestamp_ms"
        if special_metrics in metrics.keys():
            metrics.pop(special_metrics)
            metrics_schema["properties"][special_metrics] = {"type": "number"}
            metrics_schema["required"].append(special_metrics)

        for sub_metrics_name, sub_metrics_fields in metrics.items():
            obj = create_metrics_schema_objects(sub_metrics_fields)
            metrics_schema["properties"][sub_metrics_name] = obj
            metrics_schema["required"].append(sub_metrics_name)
        return metrics_schema

    if isinstance(metrics, list):
        for metrics_field in metrics:
            if isinstance(metrics_field, str):
                metrics_schema["properties"][metrics_field] = {"type": "number"}
                metrics_schema["required"].append(metrics_field)
            elif isinstance(metrics_field, dict):
                for sub_metrics_name, sub_metrics_fields in metrics_field.items():
                    obj = create_metrics_schema_objects(sub_metrics_fields)
                    metrics_schema["properties"][sub_metrics_name] = obj
                    metrics_schema["required"].append(sub_metrics_name)

        return metrics_schema

    raise Exception("Invalid schema")


def validate_fc_metrics(metrics):
    """
    This functions makes sure that all components
    of firecracker_metrics struct are present.
    """

    latency_agg_metrics_fields = [
        "min_us",
        "max_us",
        "sum_us",
    ]
    block_metrics = [
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
        "remaining_reqs_count",
        {"read_agg": latency_agg_metrics_fields},
        {"write_agg": latency_agg_metrics_fields},
    ]
    net_metrics = [
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
        "tx_remaining_reqs_count",
        {"tap_write_agg": latency_agg_metrics_fields},
    ]
    firecracker_metrics = {
        "utc_timestamp_ms": "",
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
        "block": block_metrics,
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
        "hotplug": [
            "hotplug_request_count",
            "hotplug_request_fails",
            "vcpu_hotplug_request_fails",
            "vcpus_added",
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
        "net": net_metrics,
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
            "hotplug",
            "hotplug_fails",
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
            {"exit_io_in_agg": latency_agg_metrics_fields},
            {"exit_io_out_agg": latency_agg_metrics_fields},
            {"exit_mmio_read_agg": latency_agg_metrics_fields},
            {"exit_mmio_write_agg": latency_agg_metrics_fields},
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
        if metrics_name.startswith("block_"):
            firecracker_metrics[metrics_name] = block_metrics
        if metrics_name.startswith("net_"):
            firecracker_metrics[metrics_name] = net_metrics

    firecracker_metrics_schema = create_metrics_schema_objects(firecracker_metrics)

    jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)

    def validate_missing_metrics(metrics):
        # remove some metrics and confirm that fields and not just top level metrics
        # are validated.
        temp_pop_metrics = metrics["api_server"].pop("process_startup_time_us")
        with pytest.raises(
            jsonschema.ValidationError,
            match="'process_startup_time_us' is a required property",
        ):
            jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
        metrics["api_server"]["process_startup_time_us"] = temp_pop_metrics

        if platform.machine() == "aarch64":
            temp_pop_metrics = metrics["rtc"].pop("error_count")
            with pytest.raises(
                jsonschema.ValidationError, match="'error_count' is a required property"
            ):
                jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
            metrics["rtc"]["error_count"] = temp_pop_metrics

        for vhost_user_dev in vhost_user_devices:
            temp_pop_metrics = metrics[vhost_user_dev].pop("activate_time_us")
            with pytest.raises(
                jsonschema.ValidationError,
                match="'activate_time_us' is a required property",
            ):
                jsonschema.validate(instance=metrics, schema=firecracker_metrics_schema)
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
                    if isinstance(metric_value, int):
                        if metrics_name not in metrics_calculated:
                            metrics_calculated[metrics_name] = 0
                        metrics_calculated[metrics_name] += metric_value
                    elif isinstance(metric_value, dict):
                        # this is for LatencyAggregateMetrics metrics type
                        if metrics_name not in metrics_calculated:
                            metrics_calculated[metrics_name] = {
                                "min_us": 0,
                                "max_us": 0,
                                "sum_us": 0,
                            }
                        metrics_calculated[metrics_name]["sum_us"] += metric_value[
                            "sum_us"
                        ]

        assert self.num_dev == actual_num_devices
        if self.aggr_supported:
            metrics_aggregate = fc_metrics[self.dev_name]
            assert metrics_aggregate == metrics_calculated


def get_emf_unit_for_fc_metrics(full_key):
    """Returns CloudWatch Unit for requested FC metrics key"""
    # We need to check each key because unit can be in group or key
    # e.g.  latencies_us.diff_create_snapshot and
    #       api_server.process_startup_time_us
    for key in full_key.lower().split("."):
        if key.endswith("_bytes") or key.endswith("_bytes_count"):
            return "Bytes"
        if key.endswith("_ms"):
            return "Milliseconds"
        if key.endswith("_us"):
            return "Microseconds"
    return "Count"


def flush_fc_metrics_to_cw(fc_metrics, metrics):
    """
    Flush Firecracker metrics to CloudWatch. Use an existing metrics logger with existing dimensions so that it is
    easier to correlate the metrics with the test calling it. Add a prefix "fc_metrics." to differentiate these metrics,
    this also helps to avoid using this metrics in A/B tests.
    NOTE:
        There are metrics with keywords "fail", "err", "num_faults", "panic" in their name and represent some kind of
        failure in Firecracker.  We assert that all these are zero, to catch potentially silent failure modes. This
        means the FcMonitor cannot be used in negative tests that might cause such metrics to be emitted.
    """

    # Pre-order tree traversal to convert a tree into its list of paths with dot separate segments
    def flatten_dict(node, prefix: str):
        if not isinstance(node, dict):
            return {prefix: node}

        result = {}
        for child_metric_name, child_metrics in node.items():
            result.update(flatten_dict(child_metrics, f"{prefix}.{child_metric_name}"))
        return result

    flattened_metrics = flatten_dict(fc_metrics, "fc_metrics")

    for key, value in flattened_metrics.items():
        if ".utc_timestamp_ms." in key:
            continue
        metrics.put_metric(key, value, get_emf_unit_for_fc_metrics(key))

    assert not {
        key: value
        for key, value in flattened_metrics.items()
        if "err" in key or "fail" in key or "panic" in key or "num_faults" in key
        if value
    }

    metrics.flush()


class FCMetricsMonitor(Thread):
    """
    read Firecracker metrics from the microvm every `timer` secs and
    uploads the metrics to CW. `timer` is in seconds and is default to
    60sec to match default time Firecrackers takes to dump metrics.
    We do this as a daemon thread every `timer` sec, instead of
    collecting all metrics together in the end, to retain timestamp
    of the metrics.
    """

    def __init__(self, vm, timer=60):
        Thread.__init__(self, daemon=True)
        self.vm = vm
        vm.monitors.append(self)
        self.timer = timer

        self.metrics_index = 0
        self.running = False

        self.metrics_logger = get_metrics_logger()
        self.metrics_logger.set_dimensions(
            {
                "instance": global_props.instance,
                "host_kernel": "linux-" + global_props.host_linux_version,
                "guest_kernel": vm.kernel_file.stem[2:],
            }
        )
        self.start()

    def _flush_metrics(self):
        """
        Since vm.flush_metrics provides only the latest metrics,
        we call vm.get_all_metrics() instead to be able to collect
        and upload all metrics emitted by the microvm.
        This utility function is created to keep common code in one
        place and is called every `self.timer` seconds once the daemon
        starts and then once when the daemon stops.
        """
        all_metrics = self.vm.get_all_metrics()
        for metrics in all_metrics[self.metrics_index :]:
            flush_fc_metrics_to_cw(metrics, self.metrics_logger)
            self.metrics_index += 1

    def stop(self):
        """
        Stop the daemon gracefully.
        Since we depend on the vm to provide the metrics,
        this method should be called just before killing the vm.
        We collect final metrics here in stop instead of letting it
        be collected from the "run" method because, "run" could be
        in sleep when stop is called and once it wakes out of sleep
        the "vm" might not be avaiable to provide the metrics.
        """
        if self.is_alive():
            self.running = False
            # wait for the running thread to finish
            # this should also avoid any race condition leading to
            # uploading the same metrics twice
            self.join()
            self.vm.api.actions.put(action_type="FlushMetrics")
            self._flush_metrics()

    def run(self):
        self.running = True
        while self.running is True:
            self._flush_metrics()
            # instead of a time.sleep(60), sleep in intervals of 1 sec
            # so that we can terminate the thread sooner.
            # this way we can also make stop() wait for 1 sec before
            # it collects and uploads metrics
            for _x in range(self.timer):
                time.sleep(1)
                if self.running is False:
                    break
