# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Restore and re-snapshot artifacts while retaining their vCPU register set."""

import logging

import pytest

from framework.artifacts import get_snapshot_dirs
from framework.microvm import Snapshot
from framework.utils import check_output
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

pytestmark = [pytest.mark.nonci, pin_vm_backend(VM_BACKEND_KVM)]

logger = logging.getLogger("cross_kernel_snapshot_resnapshot")

PIN_LOG_MARKERS = (
    "Snapshot omits",
    "Keeping the loaded snapshot's value",
    "Cannot list the vCPU registers that KVM reports on this host:",
    "Cannot compare the snapshot's ID register values with the host's:",
)


@pytest.mark.timeout(600)
@pytest.mark.parametrize("snapshot_dir", get_snapshot_dirs(all_artifacts=True))
def test_snap_resnapshot_from_artifacts(microvm_factory, snapshot_dir, results_dir):
    """Restore and re-snapshot a pinned artifact twice, keeping its register set.

    The artifact carries the pin, so nothing is passed here. The second
    generation restores a snapshot taken on this host, which checks that the
    pin is inherited.
    """
    snapshot = Snapshot.load_from(snapshot_dir)
    source_vmstate = snapshot.vmstate
    for generation in (1, 2):
        vm = microvm_factory.build(monitor_memory=False)
        vm.time_api_requests = False
        vm.spawn(log_level="Info")
        vm.restore_from_snapshot(snapshot)
        vm.resume()

        diagnostics = "\n".join(
            line
            for line in vm.log_data.splitlines()
            if any(marker in line for marker in PIN_LOG_MARKERS)
        )
        log_entry = (
            f"{snapshot_dir.name}, restore {generation}, microVM {vm.id}\n"
            f"{diagnostics or 'No matching pin diagnostics.'}"
        )
        logger.info("%s", log_entry)
        (results_dir / f"restore-{generation}-pin.log").write_text(
            f"{log_entry}\n", encoding="utf-8"
        )

        assert vm.state == "Running"
        for idx in range(len(vm.iface)):
            vm.ssh_iface(idx).check_output("true")

        # Record MONOTONIC before each snapshot, so the restore test measures
        # only the final restore hop.
        vm.ssh.check_output(
            "python3 -c 'import time; print(time.monotonic())' > /tmp/monotonic-before"
        )
        snapshot = vm.snapshot_full()
        vm.kill()
        check_output(
            [
                microvm_factory.binary_path / "snapshot-editor",
                "info-vmstate",
                "check-vcpu-register-pin",
                "--source-path",
                source_vmstate,
                "--vmstate-path",
                snapshot.vmstate,
            ]
        )

    snapshot_artifacts_dir = results_dir / snapshot_dir.name
    snapshot_artifacts_dir.mkdir(parents=True)
    snapshot.save_to(snapshot_artifacts_dir)
