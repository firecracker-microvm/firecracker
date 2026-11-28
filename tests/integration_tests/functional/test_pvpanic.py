# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verify pvpanic configuration, panic reporting and restore actions."""

import json
import os
import time
from pathlib import Path

import pytest
from tenacity import Retrying, stop_after_delay, wait_fixed

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel, pin_pci
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

pytestmark = [pin_guest_kernel(GUEST_KERNEL_DEFAULT), pin_vm_backend(VM_BACKEND_KVM)]

CAPABILITY = "/sys/bus/platform/drivers/pvpanic-mmio/*/capability"


def _wait_for_panic(vm):
    """Wait for a VMM panic report, not just an SSH disconnect."""
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(5), reraise=True
    ):
        with attempt:
            assert any(
                point["vmm"]["guest_panic_count"] == 1 for point in vm.get_all_metrics()
            )
    assert vm.log_data.count("Guest kernel panicked") == 1


def _trigger_guest_panic(vm):
    """Trigger SysRq asynchronously so the SSH command can return before the panic."""
    vm.ssh.check_output(
        "echo 1 > /proc/sys/kernel/sysrq; "
        "nohup sh -c 'sleep 1; echo c > /proc/sysrq-trigger' "
        ">/dev/null 2>&1 </dev/null &",
        timeout=5,
    )


def _assert_panic_action(vm, action):
    _trigger_guest_panic(vm)
    _wait_for_panic(vm)
    if action == "none":
        vm.mark_killed(timeout=10)
    else:
        assert vm.state == "Paused"
        os.kill(vm.firecracker_pid, 0)


@pin_pci(False)
def test_pvpanic_default_off(uvm):
    """Default configuration has no device and reports null before and after boot."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    assert uvm.api.vm_config.get().json()["pvpanic"] is None
    uvm.start()
    assert uvm.api.vm_config.get().json()["pvpanic"] is None
    result = uvm.ssh.run(f"cat {CAPABILITY}")
    assert result.returncode != 0


@pytest.mark.parametrize(
    "action,pci_enabled",
    [
        pytest.param("none", False, id="none-mmio"),
        pytest.param("pause", False, id="pause-mmio"),
        pytest.param("pause", True, id="pause-pci"),
    ],
    indirect=["pci_enabled"],
)
def test_pvpanic_panic_action(uvm, action, pci_enabled):
    """Verify reporting and the configured action in a two-vCPU microVM."""
    uvm.spawn()
    uvm.basic_config(vcpu_count=2)
    uvm.add_net_iface()
    uvm.api.pvpanic.put(panic_action=action)
    uvm.start()
    assert int(uvm.ssh.check_output(f"cat {CAPABILITY}").stdout.strip(), 16) == 3
    assert uvm.api.vm_config.get().json()["pvpanic"] == {"panic_action": action}
    _assert_panic_action(uvm, action)
    if action == "pause" and not pci_enabled:
        assert uvm.flush_metrics()["vmm"]["guest_panic_count"] == 1
        uvm.snapshot_full()
        uvm.resume()
        assert uvm.state == "Running"
        assert uvm.flush_metrics()["vmm"]["guest_panic_count"] == 1


@pytest.mark.parametrize(
    "saved_action,override,pci_enabled,resume_vm,expected_action",
    [
        pytest.param("pause", None, False, False, "pause", id="inherit-pause-mmio"),
        pytest.param("none", "pause", False, False, "pause", id="none-to-pause-mmio"),
        pytest.param("pause", "none", False, False, "none", id="pause-to-none-mmio"),
        pytest.param("none", "pause", True, True, "pause", id="none-to-pause-pci-auto"),
    ],
    indirect=["pci_enabled"],
)
def test_pvpanic_restore_action(
    uvm,
    microvm_factory,
    saved_action,
    override,
    pci_enabled,
    resume_vm,
    expected_action,
):
    """Override a healthy snapshot before restore and persist the effective action."""
    uvm.spawn()
    uvm.basic_config(vcpu_count=2)
    uvm.add_net_iface()
    uvm.api.pvpanic.put(panic_action=saved_action)
    uvm.start()
    snapshot = uvm.snapshot_full()
    verify_persistence = (
        saved_action == "none" and override == "pause" and not pci_enabled
    )
    original = snapshot.vmstate.read_bytes() if verify_persistence else None
    uvm.kill()
    restored = microvm_factory.build(pci=pci_enabled)
    restored.spawn()
    restored.restore_from_snapshot(
        snapshot, resume=resume_vm, pvpanic_override=override
    )
    assert restored.state == ("Running" if resume_vm else "Paused")
    assert restored.api.vm_config.get().json()["pvpanic"] == {
        "panic_action": expected_action
    }
    if not resume_vm:
        with pytest.raises(RuntimeError, match="not supported after starting"):
            restored.api.pvpanic.put(panic_action="none")
    if verify_persistence:
        assert snapshot.vmstate.read_bytes() == original
        next_snapshot = restored.snapshot_full()
        again = microvm_factory.build(pci=pci_enabled)
        again.spawn()
        again.restore_from_snapshot(next_snapshot, resume=False)
        assert again.api.vm_config.get().json()["pvpanic"] == {"panic_action": "pause"}
        again.kill()
    if not resume_vm:
        restored.resume()
    restored.wait_for_ssh_up()
    _assert_panic_action(restored, expected_action)


@pin_pci(False)
def test_pvpanic_override_requires_device(uvm, microvm_factory):
    """An override must not create a device absent from the snapshot."""
    uvm.spawn()
    uvm.basic_config()
    uvm.start()
    snapshot = uvm.snapshot_full()
    uvm.kill()
    restored = microvm_factory.build()
    restored.spawn()
    with pytest.raises(RuntimeError, match="Unknown PvPanic Device"):
        restored.restore_from_snapshot(snapshot, pvpanic_override="pause")


@pin_pci(False)
@pytest.mark.parametrize("with_api", [False, True], ids=["no-api", "api"])
def test_pvpanic_json_pause(uvm, with_api):
    """JSON-configured pauses leave the process alive, also without an API."""
    uvm.create_jailed_resource(uvm.kernel_file)
    uvm.create_jailed_resource(uvm.rootfs_file)
    uvm.add_net_iface(api=False)
    config = json.loads(
        Path("framework/vm_config_network.json").read_text(encoding="utf-8")
    )
    config["boot-source"]["kernel_image_path"] = uvm.kernel_file.name
    config["drives"][0]["path_on_host"] = uvm.rootfs_file.name
    config["drives"][0]["is_read_only"] = True
    config["pvpanic"] = {"panic_action": "pause"}
    config_file = Path(uvm.chroot()) / "pvpanic.json"
    config_file.write_text(json.dumps(config), encoding="utf-8")
    uvm.jailer.extra_args = {"config-file": config_file.name}
    if not with_api:
        uvm.jailer.extra_args["no-api"] = None
    uvm.spawn(serial_out_path=None)
    uvm.wait_for_ssh_up()
    _trigger_guest_panic(uvm)
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(5), reraise=True
    ):
        with attempt:
            assert "Guest kernel panicked" in uvm.log_data
    os.kill(uvm.firecracker_pid, 0)
    if with_api:
        assert uvm.state == "Paused"
        assert uvm.flush_metrics()["vmm"]["guest_panic_count"] == 1
    else:
        # Wait beyond the guest's panic=1 timeout to check for unintended exit.
        time.sleep(2)
        os.kill(uvm.firecracker_pid, 0)
