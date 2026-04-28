# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for Nitro Enclave direct mode in Firecracker."""

import json
import os
from pathlib import Path

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, wait_fixed

from framework.ne_host import (
    _find_initrd,
    _find_kernel,
    _get_ne_cpus,
    _is_ne_dynamic,
    requires_enclave,
)

# ---------------------------------------------------------------------------
# Test: enclave config API (no NE hardware needed)
# ---------------------------------------------------------------------------


def test_enclave_config_api(microvm_factory):
    """Verify PUT /enclave is accepted pre-boot and returned by GET /enclave."""
    kernel_path = _find_kernel()
    if not kernel_path:
        pytest.skip("Kernel not found in artifacts")

    vm = microvm_factory.build(kernel=kernel_path)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    vm.api.machine_config.put(
        vcpu_count=2,
        mem_size_mib=256,
    )

    # PUT /enclave
    vm.api.enclave.put(
        debug_mode=True,
    )

    # GET /enclave should reflect the config
    response = vm.api.enclave.get()
    config = response.json()
    assert config["debug_mode"] is True

    vm.kill()


# ---------------------------------------------------------------------------
# Test: direct (non-confidential) enclave boot with serial console
# ---------------------------------------------------------------------------


@requires_enclave
def test_enclave_direct_boot(microvm_factory, tmp_path):
    """Boot an enclave in direct PCIE mode and verify via serial console output.

    Configures serial_out_path to capture enclave serial output to a file,
    then checks for the Linux kernel boot marker in the serial output.

    Note: This PR scope is direct mode only, without enclave device transport.
    The enclave boots with just CPU, memory, and EIF — no virtio devices.
    """
    kernel = _find_kernel()
    initrd = _find_initrd()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not initrd:
        pytest.skip("No initramfs found in artifacts (needed for EIF build)")

    # In dynamic mode the kernel auto-selects CPUs; in static mode use the pool.
    vcpu_count = 2
    if _is_ne_dynamic():
        cpu_ids = None
    else:
        ne_cpus = _get_ne_cpus()
        if len(ne_cpus) < vcpu_count:
            pytest.skip(f"Not enough NE CPUs: need {vcpu_count}, have {len(ne_cpus)}")
        cpu_ids = ne_cpus[:vcpu_count]

    vm = microvm_factory.build(kernel=kernel)
    vm.spawn(validate_api=False)
    vm.time_api_requests = False

    # The EIF built from bzImage (~9 MiB) + initramfs needs modest memory.
    # NE loads the EIF at an 8 MiB offset; 256 MiB is plenty.
    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=256,
    )

    # Configure serial output to a temp file so we can read it.
    serial_file = tmp_path / "serial.log"
    serial_file.touch()
    serial_path = vm.create_jailed_resource(str(serial_file))
    vm.api.serial.put(serial_out_path=serial_path)

    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(kernel),
        initrd_path=vm.create_jailed_resource(initrd),
        boot_args="console=ttyS0 earlyprintk=serial",
    )

    enclave_kwargs = {
        "debug_mode": True,
    }
    if cpu_ids:
        enclave_kwargs["cpu_ids"] = cpu_ids
    vm.api.enclave.put(**enclave_kwargs)
    vm.api.actions.put(action_type="InstanceStart")

    # The enclave should boot. Verify process is alive.
    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            assert vm.firecracker_pid is not None
            assert os.path.exists(f"/proc/{vm.firecracker_pid}")

    # Check serial output file for kernel boot markers.
    # The serial console reader polls the info page ring buffer every 100ms.
    serial_data = ""
    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(30),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            serial_data = serial_file.read_text(encoding="utf-8")
            assert "Linux version" in serial_data, (
                "Enclave started but no 'Linux version' found in serial output "
                f"after 30s. Serial output ({len(serial_data)} bytes): "
                + repr(serial_data[:200])
            )

    vm.kill()


# ---------------------------------------------------------------------------
# Test: enclave boot via --config-file
# ---------------------------------------------------------------------------


@requires_enclave
def test_enclave_config_file_boot(microvm_factory):
    """Boot an enclave via --config-file and verify it starts.

    Unlike the API-based test, this exercises the build_microvm_from_json
    code path. Serial verification is skipped because serial_config cannot
    be set via the JSON config file before boot.
    """
    kernel = _find_kernel()
    initrd = _find_initrd()
    if not kernel:
        pytest.skip("No kernel found in artifacts")
    if not initrd:
        pytest.skip("No initramfs found in artifacts (needed for EIF build)")

    if _is_ne_dynamic():
        cpu_ids = None
        vcpu_count = 2
    else:
        ne_cpus = _get_ne_cpus()
        if len(ne_cpus) < 2:
            pytest.skip(f"Not enough NE CPUs: need 2, have {len(ne_cpus)}")
        cpu_ids = ne_cpus[:2]
        vcpu_count = len(cpu_ids)

    vm = microvm_factory.build(kernel=kernel)

    jailed_kernel = vm.create_jailed_resource(kernel)
    jailed_initrd = vm.create_jailed_resource(initrd)

    enclave_cfg = {"debug_mode": True}
    if cpu_ids:
        enclave_cfg["cpu_ids"] = cpu_ids

    config = {
        "boot-source": {
            "kernel_image_path": jailed_kernel,
            "initrd_path": jailed_initrd,
            "boot_args": "console=ttyS0 earlyprintk=serial",
        },
        "machine-config": {
            "vcpu_count": vcpu_count,
            "mem_size_mib": 256,
            "smt": False,
            "track_dirty_pages": False,
            "huge_pages": "None",
        },
        "drives": [],
        "network-interfaces": [],
        "enclave": enclave_cfg,
    }

    config_path = Path(vm.chroot()) / "vm_config.json"
    config_path.write_text(json.dumps(config))
    vm.jailer.extra_args = {"config-file": config_path.name}

    vm.spawn(serial_out_path=None)

    for attempt in Retrying(
        wait=wait_fixed(0.1),
        stop=stop_after_delay(5),
        retry=retry_if_exception_type(AssertionError),
    ):
        with attempt:
            assert vm.firecracker_pid is not None
            assert os.path.exists(f"/proc/{vm.firecracker_pid}")
            assert vm.state == "Running"

    vm.kill()
