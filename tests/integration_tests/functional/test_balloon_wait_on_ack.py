# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verify VIRTIO_BALLOON_F_HINT_WAIT_ON_ACK negotiation with a patched guest.

This test is gated on `@pytest.mark.requires_patched_kernel` and is excluded
from every CI run (regular and nightly) by `tests/pytest.ini`. It assumes the
6.1 artifact `vmlinux` has been replaced in place with a build that carries
Jack Thomson's `virtio_balloon: Support wait on ACK for hinting` patch (see
fc-kernels/patches/6.1.158/0001-virtio_balloon-Support-wait-on-ACK-for-hinting.patch).

To run it after swapping in the patched kernel:

    tools/devtool -y test -- -m requires_patched_kernel \\
        tests/integration_tests/functional/test_balloon_wait_on_ack.py

If the kernel is *not* patched, the bit-6 assertion fails with a clear
"did you replace the kernel?" message — that's the expected signal that
the prerequisite is missing.
"""

import pytest

VIRTIO_ID_BALLOON = 5
VIRTIO_BALLOON_F_FREE_PAGE_HINT = 3
VIRTIO_BALLOON_F_HINT_WAIT_ON_ACK = 6


def _read_balloon_features(vm):
    """Return the negotiated features bitstring of the balloon virtio device.

    Linux exposes negotiated features via
    `/sys/bus/virtio/devices/virtio*/features` as one ASCII char per bit,
    LSB-first, plus a trailing newline. See `features_show` in upstream
    `drivers/virtio/virtio.c`.
    """
    # /sys/bus/virtio/devices/virtio*/device is a 0x%04x string with
    # trailing newline, e.g. "0x0005\n" for balloon. Match by hex value.
    cmd = (
        "for d in /sys/bus/virtio/devices/virtio*; do "
        '  if [ "$(cat "$d/device")" = "0x0005" ]; then '
        '    cat "$d/features"; '
        "    exit 0; "
        "  fi; "
        "done; "
        "exit 1"
    )
    rc, stdout, stderr = vm.ssh.run(cmd)
    assert rc == 0, f"balloon virtio device not found in guest sysfs: {stderr}"
    return stdout.strip()


@pytest.mark.requires_patched_kernel
def test_fph_wait_on_ack_negotiated(uvm_plain_6_1):
    """The guest negotiates bit 6 (WAIT_ON_ACK) when FPH is enabled."""
    vm = uvm_plain_6_1
    vm.spawn()
    vm.basic_config(vcpu_count=1, mem_size_mib=256)
    vm.add_net_iface()
    vm.api.balloon.put(
        amount_mib=0,
        deflate_on_oom=False,
        free_page_hinting=True,
    )
    vm.start()

    features = _read_balloon_features(vm)

    # Format: LSB-first '0'/'1' string.
    assert (
        features[VIRTIO_BALLOON_F_FREE_PAGE_HINT] == "1"
    ), f"FREE_PAGE_HINT (bit 3) not negotiated; features={features!r}"
    assert features[VIRTIO_BALLOON_F_HINT_WAIT_ON_ACK] == "1", (
        f"HINT_WAIT_ON_ACK (bit 6) not negotiated; features={features!r}. "
        "The guest kernel likely lacks the wait-on-ACK patch — did you "
        "forget to replace the 6.1 artifact vmlinux with a patched build? "
        "See the module docstring."
    )
