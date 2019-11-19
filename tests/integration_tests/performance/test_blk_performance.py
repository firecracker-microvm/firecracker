# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""
import json
import os
import pytest

import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error

# Block device size in MB.
BLOCK_DEVICE_SIZE = 2048
# Iteration duration in seconds.
ITERATION_DURATION = 120

FIO_BLOCK_SIZES = [65536, 4096, 1024, 512]
FIO_TEST_MODES = ["randread", "randrw", "read", "readwrite"]

FIO_RESULT_OPS = ["read", "write"]
FIO_RESULT_METRICS = ["iops", "bw"]
FIO_RESULT_VALUES = ["min", "mean", "max"]


def parse_fio_result(json_result, mode, bs):
    """Parse fio json result and collect metrics."""
    job = json_result["jobs"][0]

    result = {
        "test": "{}-{}".format(bs, mode),
    }

    for op in FIO_RESULT_OPS:
        for metric in FIO_RESULT_METRICS:
            for value in FIO_RESULT_VALUES:
                result_name = "{}_{}_{}".format(op, metric, value)
                result_metric = "{}_{}".format(metric, value)
                result_value = int(job[op][result_metric])
                if metric == "bw":
                    # Bandwidth in MB/s
                    result[result_name] = round(result_value/1024, 2)
                else:
                    result[result_name] = result_value
    return result


def run_fio(ssh_connection, mode, bs):
    """Run a fio test in the specified mode with block size bs."""
    # Clear host page cache first.
    os.system("sync; echo 1 > /proc/sys/vm/drop_caches")

    cmd = ("fio --name={mode}-{bs} --rw={mode} --bs={bs} --filename=/dev/vdb "
           "--time_based  --size={block_size}M --direct=1 --ioengine=libaio "
           "--iodepth=32 --numjobs=1  --randrepeat=0 --runtime={duration} "
           "--output-format=json").format(
           mode=mode, bs=bs, block_size=BLOCK_DEVICE_SIZE,
           duration=ITERATION_DURATION)

    # print(cmd)
    _, stdout, stderr = ssh_connection.execute_command(cmd)

    assert stderr.read().decode("utf-8") == ""

    fio_result = json.loads(stdout.read().decode("utf-8"))
    result = parse_fio_result(fio_result, mode, bs)

    print(json.dumps(result, indent=4))
    return result


@pytest.mark.timeout(3600)
@pytest.mark.env("benchmark")
def test_block_device_performance(test_microvm_with_ssh, network_config):
    """Execute block device emulation benchmarking scenarios."""
    microvm = test_microvm_with_ssh
    microvm.spawn()
    microvm.basic_config(mem_size_mib=1024)

    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(microvm.fsfiles, 'scratch'),
        BLOCK_DEVICE_SIZE
    )

    response = microvm.drive.put(
        drive_id='scratch',
        path_on_host=microvm.create_jailed_resource(fs.path),
        is_root_device=False,
        is_read_only=False
    )
    assert microvm.api_session.is_status_no_content(response.status_code)

    _tap, _, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)
    results = []
    for mode in FIO_TEST_MODES:
        for bs in FIO_BLOCK_SIZES:
            results.append(run_fio(ssh_connection, mode, bs))

    print("Results: ")
    print(json.dumps(results, indent=4))

    with open('test_blk_performance.json', 'w') as outfile:
        json.dump(results, outfile, indent=4)

    # TODO: Compare values with a the baseline and fail test if required.
