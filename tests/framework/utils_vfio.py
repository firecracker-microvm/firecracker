# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers to bind host NVMe PCI devices to vfio-pci for passthrough tests."""

import os
import re
from pathlib import Path

# PCI class code of an NVMe controller
NVME_PCI_CLASS = "0x010802"
NVME_NAMESPACE_REGEX = re.compile(r"nvme[0-9]+n[0-9]+")
PCI_DEVICES_PATH = Path("/sys/bus/pci/devices")
PCI_DRIVERS_PROBE_PATH = Path("/sys/bus/pci/drivers_probe")
PCI_SBDF_REGEX = re.compile(
    r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", re.IGNORECASE
)


def vfio_nvme_driver_name(pci_device_path):
    """Name of the driver bound to the PCI device at `pci_device_path`, or None."""
    assert pci_device_path.is_dir()
    driver_path = pci_device_path / "driver"
    if not driver_path.exists():
        return None
    return driver_path.resolve().name


def vfio_nvme_pci_class(pci_device_path):
    """PCI class code of the PCI device at `pci_device_path`."""
    pci_class_path = pci_device_path / "class"
    return pci_class_path.read_text(encoding="ascii").strip()


def vfio_nvme_find_pci_device(device, allow_unclaimed):
    """
    PCI device of `device`, which is either a PCI SBDF or an NVMe block device.
    The block device does not exist if a previous run left the device on
    vfio-pci or without a driver. If `allow_unclaimed` is set, use the only
    NVMe PCI device not claimed by the host driver in this case.
    """
    if PCI_SBDF_REGEX.fullmatch(device):
        pci_device_path = PCI_DEVICES_PATH / device.lower()
        if not pci_device_path.exists():
            raise RuntimeError(f"PCI device {device} does not exist")
        return pci_device_path

    # Resolve symlinks like /dev/sdf -> /dev/nvme1n1. The PCI function belongs
    # to the controller (nvme1), not to the namespace (nvme1n1).
    block_device_path = Path(device).resolve()
    controller_name = re.sub(r"n[0-9]+$", "", block_device_path.name)
    controller_device_path = Path("/sys/class/nvme") / controller_name / "device"
    pci_device_path = controller_device_path.resolve()
    pci_class_path = pci_device_path / "class"
    if pci_class_path.exists():
        return pci_device_path
    if not allow_unclaimed:
        raise RuntimeError(f"Can not resolve {device} to an NVMe PCI device")

    sbdfs = []
    for pci_device_path in PCI_DEVICES_PATH.iterdir():
        if vfio_nvme_pci_class(pci_device_path) != NVME_PCI_CLASS:
            continue
        driver_name = vfio_nvme_driver_name(pci_device_path)
        if driver_name is None or driver_name == "vfio-pci":
            sbdfs.append(pci_device_path.name)
    # Do not guess between several devices, since a wrong guess can overwrite
    # someone's data
    if len(sbdfs) != 1:
        raise RuntimeError(
            f"Can not resolve {device} to an NVMe PCI device. "
            f"NVMe PCI devices not claimed by the host driver: {sbdfs}"
        )
    return PCI_DEVICES_PATH / sbdfs[0]


def vfio_nvme_check_unused(pci_device_path):
    """
    Check the host does not use any namespace of the NVMe controller at
    `pci_device_path`. Exclusive open of a block device fails with EBUSY if it
    or any of its partitions is mounted or otherwise claimed.
    """
    # Namespaces only exist while the controller is bound to the nvme driver
    nvme_path = pci_device_path / "nvme"
    if not nvme_path.exists():
        return
    for controller_path in nvme_path.iterdir():
        namespace_count = 0
        for namespace_path in controller_path.iterdir():
            if not NVME_NAMESPACE_REGEX.fullmatch(namespace_path.name):
                continue
            fd = os.open(f"/dev/{namespace_path.name}", os.O_RDONLY | os.O_EXCL)
            os.close(fd)
            namespace_count += 1
        # Native NVMe multipath names the namespaces `nvmeXcYnZ` instead
        assert 0 < namespace_count, f"No namespaces found for {controller_path.name}"


def vfio_nvme_unbind(pci_device_path):
    """Unbind the PCI device at `pci_device_path` from its driver, if any."""
    if vfio_nvme_driver_name(pci_device_path) is None:
        return
    unbind_path = pci_device_path / "driver" / "unbind"
    unbind_path.write_text(pci_device_path.name, encoding="ascii")


def vfio_nvme_rebind(pci_device_path, driver_override):
    """
    Rebind the PCI device at `pci_device_path` to `driver_override`. An empty
    `driver_override` lets the default driver claim the device.
    """
    # Set the override before unbinding, so no other driver claims the device
    driver_override_path = pci_device_path / "driver_override"
    driver_override_path.write_text(driver_override + "\n", encoding="ascii")
    vfio_nvme_unbind(pci_device_path)
    PCI_DRIVERS_PROBE_PATH.write_text(pci_device_path.name, encoding="ascii")
