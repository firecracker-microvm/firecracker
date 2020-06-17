# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import logging
import platform
import pytest
from conftest import _test_images_s3_bucket
from framework.artifacts import ArtifactCollection, ArtifactSet
from framework.matrix import TestMatrix, TestContext
from framework.builder import MicrovmBuilder
import host_tools.network as net_tools  # pylint: disable=import-error


def _test_pause_resume(context):
    logger = context.custom['logger']
    vm_builder = context.custom['builder']

    logger.info("Testing microvm: \"{}\" with kernel {} and disk {} "
                .format(context.microvm.name(),
                        context.kernel.name(),
                        context.disk.name()))
    rw_disk = context.disk.copy()
    # Local artifacts created with copy() do not reference ssh keys.
    ssh_key = context.disk.ssh_key()

    microvm = vm_builder.build(kernel=context.kernel,
                               disks=[rw_disk],
                               ssh_key=ssh_key,
                               config=context.microvm)
    tap = microvm.ssh_network_config(context.custom['network_config'], '1')

    # Pausing the microVM before being started is not allowed.
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_bad_request(response.status_code)

    # Resuming the microVM before being started is also not allowed.
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_bad_request(response.status_code)

    microvm.start()

    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Verify guest is active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    # Pausing the microVM after it's been started is successful.
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is no longer active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code != 0

    # Pausing the microVM when it is already `Paused` is allowed
    # (microVM remains in `Paused` state).
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Resuming the microVM is successful.
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is active again.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    # Resuming the microVM when it is already `Resumed` is allowed
    # (microVM remains in the running state).
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is still active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    microvm.kill()
    del tap


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_pause_resume(network_config,
                      bin_cloner_path):
    """Test scenario: boot/pause/resume for all available configurations."""
    logger = logging.getLogger("pause_resume")
    # Currently, artifacts share the bucket with all other resources.
    artifact_collection = ArtifactCollection(_test_images_s3_bucket())

    microvm_artifacts = ArtifactSet(artifact_collection.microvms())
    kernel_artifacts = ArtifactSet(artifact_collection.kernels())
    # Restrict root fs to ubuntu.
    disk_artifacts = ArtifactSet(artifact_collection.disks(keyword="ubuntu"))

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'builder': MicrovmBuilder(bin_cloner_path),
        'network_config': network_config,
        'logger': logger
    }

    # Create the test matrix.
    test_matrix = TestMatrix(context=test_context,
                             artifact_sets=[
                                 microvm_artifacts,
                                 kernel_artifacts,
                                 disk_artifacts
                             ])

    test_matrix.run_test(_test_pause_resume)
