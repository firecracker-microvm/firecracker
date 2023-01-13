# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import json
import logging
import os
import platform
import pytest

from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.defs import DEFAULT_TEST_IMAGES_S3_BUCKET
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.utils import (
    eager_map,
    CpuMap,
    get_firecracker_version_from_toml,
    get_kernel_version,
    is_io_uring_supported,
)
from framework.utils_cpuid import get_instance_type
from framework.stats import core, consumer, producer, types, criteria, function
from integration_tests.performance.utils import handle_failure

import host_tools.logging as log_tools

# How many latencies do we sample per test.
SAMPLE_COUNT = 3
USEC_IN_MSEC = 1000
PLATFORM = platform.machine()
ENGINES = ["Sync"]

if is_io_uring_supported():
    ENGINES.append("Async")

# Latencies in milliseconds.
# The latency for snapshot creation has high variance due to scheduler noise.
# The issue is tracked here:
# https://github.com/firecracker-microvm/firecracker/issues/2346
# TODO: Update baseline values after fix.
CREATE_LATENCY_BASELINES = {
    "x86_64": {
        "2vcpu_256mb.json": {"FULL": {"target": 180}, "DIFF": {"target": 70}},
        "2vcpu_512mb.json": {
            "FULL": {"target": 280},
            "DIFF": {"target": 90},
        },
    },
    "aarch64": {
        "2vcpu_256mb.json": {
            "FULL": {"target": 160},
            "DIFF": {"target": 70},
        },
        "2vcpu_512mb.json": {
            "FULL": {"target": 300},
            "DIFF": {"target": 75},
        },
    },
}

# The latencies for x86 are pretty high due to a design
# in the cgroups V1 implementation in the kernel. We recommend
# switching to cgroups v2 for much lower snap resume latencies.
# More details on this:
# https://github.com/firecracker-microvm/firecracker/issues/2027
# Latencies for snap resume on cgroups V2 can be found in our
# long-running performance configs (i.e. integration_tests/performance/configs).
LOAD_LATENCY_BASELINES = {
    "x86_64": {
        "m5d.metal": {
            "4.14": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 9},
                    "2vcpu_512mb.json": {"target": 9},
                }
            },
            "5.10": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 70},
                    "2vcpu_512mb.json": {"target": 75},
                },
                "async": {
                    "2vcpu_256mb.json": {"target": 210},
                    "2vcpu_512mb.json": {"target": 210},
                },
            },
        },
        "m6a.metal": {
            "4.14": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 15},
                    "2vcpu_512mb.json": {"target": 19},
                }
            },
            "5.10": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 60},
                    "2vcpu_512mb.json": {"target": 60},
                },
                "async": {
                    "2vcpu_256mb.json": {"target": 190},
                    "2vcpu_512mb.json": {"target": 190},
                },
            },
        },
        "m6i.metal": {
            "4.14": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 9},
                    "2vcpu_512mb.json": {"target": 9},
                }
            },
            "5.10": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 70},
                    "2vcpu_512mb.json": {"target": 70},
                },
                "async": {
                    "2vcpu_256mb.json": {"target": 245},
                    "2vcpu_512mb.json": {"target": 245},
                },
            },
        },
    },
    "aarch64": {
        "m6g.metal": {
            "4.14": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 2},
                    "2vcpu_512mb.json": {"target": 2},
                }
            },
            "5.10": {
                "sync": {
                    "2vcpu_256mb.json": {"target": 2},
                    "2vcpu_512mb.json": {"target": 2},
                },
                "async": {
                    "2vcpu_256mb.json": {"target": 320},
                    "2vcpu_512mb.json": {"target": 330},
                },
            },
        }
    },
}


def snapshot_create_measurements(vm_type, snapshot_type):
    """Define measurements for snapshot create tests."""
    latency = types.MeasurementDef.create_measurement(
        "latency",
        "ms",
        [function.Max("max")],
        {
            "max": criteria.LowerThan(
                CREATE_LATENCY_BASELINES[platform.machine()][vm_type][
                    "FULL" if snapshot_type == SnapshotType.FULL else "DIFF"
                ]
            )
        },
    )

    return [latency]


def snapshot_resume_measurements(vm_type, io_engine):
    """Define measurements for snapshot resume tests."""
    load_latency = LOAD_LATENCY_BASELINES[platform.machine()][get_instance_type()][
        get_kernel_version(level=1)
    ][io_engine][vm_type]

    latency = types.MeasurementDef.create_measurement(
        "latency",
        "ms",
        [function.Max("max")],
        {"max": criteria.LowerThan(load_latency)},
    )

    return [latency]


def snapshot_create_producer(
    logger, vm, disks, ssh_key, target_version, metrics_fifo, snapshot_type
):
    """Produce results for snapshot create tests."""
    snapshot_builder = SnapshotBuilder(vm)
    snapshot_builder.create(
        disks=disks,
        ssh_key=ssh_key,
        snapshot_type=snapshot_type,
        target_version=target_version,
        use_ramdisk=True,
    )
    metrics = vm.flush_metrics(metrics_fifo)

    if snapshot_type == SnapshotType.FULL:
        value = metrics["latencies_us"]["full_create_snapshot"] / USEC_IN_MSEC
    else:
        value = metrics["latencies_us"]["diff_create_snapshot"] / USEC_IN_MSEC

    logger.info("Latency {} ms".format(value))

    return value


def snapshot_resume_producer(logger, vm_builder, snapshot, snapshot_type, use_ramdisk):
    """Produce results for snapshot resume tests."""
    microvm, metrics_fifo = vm_builder.build_from_snapshot(
        snapshot,
        resume=True,
        diff_snapshots=snapshot_type == SnapshotType.DIFF,
        use_ramdisk=use_ramdisk,
    )

    # Attempt to connect to resumed microvm.
    # Verify if guest can run commands.
    exit_code, _, _ = microvm.ssh.execute_command("ls")
    assert exit_code == 0

    value = 0
    # Parse all metric data points in search of load_snapshot time.
    metrics = microvm.get_all_metrics(metrics_fifo)
    for data_point in metrics:
        metrics = json.loads(data_point)
        cur_value = metrics["latencies_us"]["load_snapshot"] / USEC_IN_MSEC
        if cur_value > 0:
            value = cur_value
            break

    logger.info("Latency {} ms".format(value))

    return value


def _test_snapshot_create_latency(context):
    logger = context.custom["logger"]
    vm_builder = context.custom["builder"]
    snapshot_type = context.custom["snapshot_type"]
    file_dumper = context.custom["results_file_dumper"]
    diff_snapshots = snapshot_type == SnapshotType.DIFF

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()

    logger.info(
        "Fetching firecracker/jailer versions from {}.".format(
            DEFAULT_TEST_IMAGES_S3_BUCKET
        )
    )
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    firecracker_versions = artifacts.firecracker_versions(
        # v1.0.0 breaks snapshot compatibility with older versions.
        min_version="1.0.0",
        max_version=get_firecracker_version_from_toml(),
    )
    assert len(firecracker_versions) > 0

    # Test snapshot creation for every supported target version.
    for target_version in firecracker_versions:
        logger.info(
            """Measuring snapshot create({}) latency for target
        version: {} and microvm: \"{}\", kernel {}, disk {} """.format(
                snapshot_type,
                target_version,
                context.microvm.name(),
                context.kernel.name(),
                context.disk.name(),
            )
        )

        # Create a fresh microVM from artifacts.
        vm_instance = vm_builder.build(
            kernel=context.kernel,
            disks=[rw_disk],
            ssh_key=ssh_key,
            config=context.microvm,
            diff_snapshots=diff_snapshots,
            use_ramdisk=True,
        )
        vm = vm_instance.vm
        # Configure metrics system.
        metrics_fifo_path = os.path.join(vm.path, "metrics_fifo")
        metrics_fifo = log_tools.Fifo(metrics_fifo_path)

        response = vm.metrics.put(
            metrics_path=vm.create_jailed_resource(metrics_fifo.path)
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        vm.start()

        # Check if the needed CPU cores are available. We have the API
        # thread, VMM thread and then one thread for each configured vCPU.
        assert CpuMap.len() >= 2 + vm.vcpus_count

        # Pin uVM threads to physical cores.
        current_cpu_id = 0
        assert vm.pin_vmm(current_cpu_id), "Failed to pin firecracker thread."
        current_cpu_id += 1
        assert vm.pin_api(current_cpu_id), "Failed to pin fc_api thread."
        for idx_vcpu in range(vm.vcpus_count):
            current_cpu_id += 1
            assert vm.pin_vcpu(
                idx_vcpu, current_cpu_id + idx_vcpu
            ), f"Failed to pin fc_vcpu {idx_vcpu} thread."

        st_core = core.Core(
            name="snapshot_create_full_latency"
            if snapshot_type == SnapshotType.FULL
            else "snapshot_create_diff_latency",
            iterations=SAMPLE_COUNT,
        )

        prod = producer.LambdaProducer(
            func=snapshot_create_producer,
            func_kwargs={
                "logger": logger,
                "vm": vm,
                "disks": [rw_disk],
                "ssh_key": ssh_key,
                "target_version": target_version,
                "metrics_fifo": metrics_fifo,
                "snapshot_type": snapshot_type,
            },
        )

        cons = consumer.LambdaConsumer(
            func=lambda cons, result: cons.consume_stat(
                st_name="max", ms_name="latency", value=result
            ),
            func_kwargs={},
        )
        eager_map(
            cons.set_measurement_def,
            snapshot_create_measurements(context.microvm.name(), snapshot_type),
        )

        st_core.add_pipe(producer=prod, consumer=cons, tag=context.microvm.name())

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(file_dumper, err)

    file_dumper.dump(result)


def _test_snapshot_resume_latency(context):
    logger = context.custom["logger"]
    vm_builder = context.custom["builder"]
    snapshot_type = context.custom["snapshot_type"]
    file_dumper = context.custom["results_file_dumper"]
    io_engine = context.custom["io_engine"]
    diff_snapshots = snapshot_type == SnapshotType.DIFF

    logger.info(
        """Measuring snapshot resume({}) latency for microvm: \"{}\",
    kernel {}, disk {} """.format(
            snapshot_type,
            context.microvm.name(),
            context.kernel.name(),
            context.disk.name(),
        )
    )

    # Create a rw copy artifact.
    rw_disk = context.disk.copy()
    # Get ssh key from read-only artifact.
    ssh_key = context.disk.ssh_key()
    # Create a fresh microvm from artifacts.
    vm_instance = vm_builder.build(
        kernel=context.kernel,
        disks=[rw_disk],
        ssh_key=ssh_key,
        config=context.microvm,
        diff_snapshots=diff_snapshots,
        use_ramdisk=True,
        io_engine=io_engine,
    )
    basevm = vm_instance.vm
    basevm.start()

    # Check if guest works.
    exit_code, _, _ = basevm.ssh.execute_command("ls")
    assert exit_code == 0

    logger.info("Create {}.".format(snapshot_type))
    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)

    snapshot = snapshot_builder.create(
        [rw_disk.local_path()], ssh_key, snapshot_type, use_ramdisk=True
    )

    basevm.kill()

    st_core = core.Core(name="snapshot_resume_latency", iterations=SAMPLE_COUNT)

    prod = producer.LambdaProducer(
        func=snapshot_resume_producer,
        func_kwargs={
            "logger": logger,
            "vm_builder": vm_builder,
            "snapshot": snapshot,
            "snapshot_type": snapshot_type,
            "use_ramdisk": True,
        },
    )

    cons = consumer.LambdaConsumer(
        func=lambda cons, result: cons.consume_stat(
            st_name="max", ms_name="latency", value=result
        ),
        func_kwargs={},
    )
    eager_map(
        cons.set_measurement_def,
        snapshot_resume_measurements(context.microvm.name(), io_engine.lower()),
    )

    st_core.add_pipe(producer=prod, consumer=cons, tag=context.microvm.name())

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(file_dumper, err)

    file_dumper.dump(result)


ARTIFACTS = ArtifactCollection(_test_images_s3_bucket())


@pytest.mark.parametrize("io_engine", ENGINES)
@pytest.mark.parametrize(
    "microvm", ARTIFACTS.microvms(keyword="2vcpu_512mb"), ids=lambda uvm: uvm.name()
)
def test_older_snapshot_resume_latency(
    bin_cloner_path, results_file_dumper, firecracker_release, io_engine, microvm
):
    """
    Test scenario: Older snapshot load performance measurement.

    With each previous firecracker version, create a snapshot and try to
    restore in current version.

    @type: performance
    """
    logger = logging.getLogger("old_snapshot_load")

    builder = MicrovmBuilder(bin_cloner_path)
    snapshot_type = SnapshotType.FULL
    microvm.download()
    jailer = firecracker_release.jailer()
    fc_version = firecracker_release.base_name()[1:]
    logger.info("Firecracker version: %s", fc_version)
    logger.info("Source Firecracker: %s", firecracker_release.local_path())
    logger.info("Source Jailer: %s", jailer.local_path())

    # Create a fresh microvm with the binary artifacts.
    vm_instance = builder.build_vm_micro(
        firecracker_release.local_path(), jailer.local_path()
    )
    basevm = vm_instance.vm
    basevm.start()

    # Check if guest works.
    exit_code, _, _ = basevm.ssh.execute_command("ls")
    assert exit_code == 0

    # The snapshot builder expects disks as paths, not artifacts.
    disks = []
    for disk in vm_instance.disks:
        disks.append(disk.local_path())

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(basevm)
    snapshot = snapshot_builder.create(disks, vm_instance.ssh_key, snapshot_type)

    basevm.kill()

    st_core = core.Core(name="older_snapshot_resume_latency", iterations=SAMPLE_COUNT)

    prod = producer.LambdaProducer(
        func=snapshot_resume_producer,
        func_kwargs={
            "logger": logger,
            "vm_builder": builder,
            "snapshot": snapshot,
            "snapshot_type": snapshot_type,
            "use_ramdisk": False,
        },
    )

    cons = consumer.LambdaConsumer(
        func=lambda cons, result: cons.consume_stat(
            st_name="max", ms_name="latency", value=result
        ),
        func_kwargs={},
    )
    eager_map(
        cons.set_measurement_def,
        snapshot_resume_measurements(microvm.name(), io_engine.lower()),
    )

    st_core.add_pipe(producer=prod, consumer=cons, tag=microvm.name())

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(results_file_dumper, err)

    results_file_dumper.dump(result)


def test_snapshot_create_full_latency(
    network_config, bin_cloner_path, results_file_dumper
):
    """
    Test scenario: Full snapshot create performance measurement.

    @type: performance
    """
    logger = logging.getLogger("snapshot_sequence")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: Linux 4.14
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 256/512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_256mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="2vcpu_512mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "network_config": network_config,
        "logger": logger,
        "snapshot_type": SnapshotType.FULL,
        "name": "create_full_latency",
        "results_file_dumper": results_file_dumper,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )

    test_matrix.run_test(_test_snapshot_create_latency)


def test_snapshot_create_diff_latency(
    network_config, bin_cloner_path, results_file_dumper
):
    """
    Test scenario: Diff snapshot create performance measurement.

    @type: performance
    """
    logger = logging.getLogger("snapshot_sequence")
    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: All supported ones
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 256/512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_256mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="2vcpu_512mb"))
    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "network_config": network_config,
        "logger": logger,
        "snapshot_type": SnapshotType.DIFF,
        "name": "create_diff_latency",
        "results_file_dumper": results_file_dumper,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )

    test_matrix.run_test(_test_snapshot_create_latency)


@pytest.mark.parametrize("io_engine", ENGINES)
def test_snapshot_resume_latency(
    network_config, bin_cloner_path, results_file_dumper, io_engine
):
    """
    Test scenario: Snapshot load performance measurement.

    @type: performance
    """
    logger = logging.getLogger("snapshot_load")

    artifacts = ArtifactCollection(_test_images_s3_bucket())
    # Testing matrix:
    # - Guest kernel: All supported ones
    # - Rootfs: Ubuntu 18.04
    # - Microvm: 2vCPU with 256/512 MB RAM
    # TODO: Multiple microvm sizes must be tested in the async pipeline.
    microvm_artifacts = ArtifactSet(artifacts.microvms(keyword="2vcpu_256mb"))
    microvm_artifacts.insert(artifacts.microvms(keyword="2vcpu_512mb"))

    kernel_artifacts = ArtifactSet(artifacts.kernels())
    disk_artifacts = ArtifactSet(artifacts.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        "builder": MicrovmBuilder(bin_cloner_path),
        "network_config": network_config,
        "logger": logger,
        "snapshot_type": SnapshotType.FULL,
        "name": "resume_latency",
        "results_file_dumper": results_file_dumper,
        "io_engine": io_engine,
    }

    # Create the test matrix.
    test_matrix = TestMatrix(
        context=test_context,
        artifact_sets=[microvm_artifacts, kernel_artifacts, disk_artifacts],
    )

    test_matrix.run_test(_test_snapshot_resume_latency)
