# Device Passthrough

> [!WARNING]
>
> This feature is currently in
> [Developer Preview](RELEASE_POLICY.md#developer-preview-features). It may have
> limitations, and its API or behavior may change in future releases.

Device passthrough is a mechanism which enables a VM direct access to some
physical device. Currently it is implemented using Linux VFIO framework.

## What is VFIO

VFIO (Virtual Function I/O) is a Linux kernel framework that allows userspace
programs to directly access physical devices in a secure, IOMMU-protected
environment. Firecracker uses VFIO to pass through PCI devices from the host
into the guest, giving the guest near-native performance access to physical
hardware such as GPUs, network adapters, NVMe drives etc.

## Prerequisites

VFIO passthrough requires:

- Firecracker must be started with the `--enable-pci` flag since VFIO devices
  are PCI devices.
- An IOMMU (Intel VT-d, AMD-Vi, or ARM SMMU) must be enabled on the host.
- The host must have the `vfio` and `vfio-pci` kernel modules loaded.
- The target PCI device must be unbound from its native kernel driver and bound
  to the `vfio-pci` driver.
- All devices in the same IOMMU group must be bound to `vfio-pci`.
- The host must provide the legacy VFIO container interface (`/dev/vfio/vfio`,
  `CONFIG_VFIO_CONTAINER`). The `iommufd` based VFIO device cdev interface is
  not supported.
- The Firecracker process must have read/write access to `/dev/vfio/vfio` and
  `/dev/vfio/<iommu group>`, and be able to read the
  `/sys/bus/pci/devices/<sbdf>/iommu_group` link.
- The `RLIMIT_MEMLOCK` of the Firecracker process must be at least the guest
  memory size, unless the process has `CAP_IPC_LOCK`. Otherwise attaching the
  device fails with `Out of memory (os error 12)` and the host kernel logs
  `RLIMIT_MEMLOCK exceeded`.

## How to bind device to `vfio-pci` driver

To bind a device (e.g. `0000:01:02.3`) to `vfio-pci`:

```bash
# Unbind from current driver
echo "0000:01:02.3" > /sys/bus/pci/devices/0000:01:02.3/driver/unbind
# Bind to vfio-pci
echo "vfio-pci" > /sys/bus/pci/devices/0000:01:02.3/driver_override
echo "0000:01:02.3" > /sys/bus/pci/drivers/vfio-pci/bind
```

## Configuration

Firecracker exposes the following configuration options for VFIO devices:

- `id` - unique identifier for the device
- `sbdf` - host PCI device identifier, accepted in many forms:
  - full SBDF: `0000:01:02.3`
  - short BDF: `01:02.3`

The guest does not see the host SBDF. The device gets a new address on the guest
PCI topology (e.g. `0000:00:01.0`).

### Config file

```json
"device-passthrough": [
    {
      "id": "device0",
      "sbdf": "0000:01:02.3"
    }
]
```

### API

#### Add device

The same `PUT /device-passthrough/{id}` endpoint works both before and after
boot. Devices added before boot are placed on the PCI root bus. Devices added
after boot are hot-plugged behind a free PCIe root port, which requires
`pcie_hotplug_ports` to be set in the machine configuration (see
[Device Hotplugging](device-hotplug.md)). Updating an existing device after boot
is not supported.

```console
curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/device-passthrough/device0' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
         \"id\": \"device0\",
         \"sbdf\": \"0000:01:02.3\"
    }"
```

#### Remove device

A VFIO device can be removed at runtime via `DELETE /device-passthrough/{id}`:

```console
curl --unix-socket $socket_location -i \
    -X DELETE 'http://localhost/device-passthrough/device0'
```

Hot-unplug is only valid after the microVM has booted and only for devices
behind PCIe root ports, i.e. devices hot-plugged after boot. As with virtio
devices, the removal is graceful by default and the optional `force` flag
removes the device immediately (see
[Hot-unplugging a device](device-hotplug.md#hot-unplugging-a-device)). Once
removed, the device is detached from the guest PCI bus and all associated
resources (DMA mappings, interrupts, BAR memory) are released.

## Booting from a VFIO device

A passthrough block device (e.g. an NVMe SSD bound to `vfio-pci`) can serve as
the guest's root filesystem instead of a virtio-block drive. Firecracker does
not auto-detect this; you must point the guest kernel at the right device via
the boot arguments.

1. Configure the VFIO device as usual (see [Configuration](#configuration)) and
   make sure no `is_root_device: true` virtio drive is configured.

1. In the boot source, set `boot_args` so that `root=` names the block device
   the guest kernel will see for the passthrough device. For an NVMe namespace
   that will appear as `/dev/nvme0n1`:

   ```json
   "boot-source": {
       "kernel_image_path": "/path/to/vmlinux",
       "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/nvme0n1 ro"
   }
   ```

   Use `root=/dev/nvme0n1p1` (or similar) if the rootfs lives on a partition,
   and adjust the device name for non-NVMe devices (`/dev/sda`, etc.).

Notes:

- The guest kernel must include the driver for the passthrough device (e.g.
  `CONFIG_BLK_DEV_NVME=y`) and any filesystem it uses, either built-in or
  available as an initrd-loadable module.
- If the device is hot-plugged after boot it cannot be the root device — the
  kernel has already mounted root by then. Use cold-boot configuration for the
  root device.
- With multiple passthrough block devices the guest device names (e.g.
  `nvme0n1`, `nvme1n1`) are not guaranteed to be stable across boots. Use
  `root=PARTUUID=<uuid>` on a partitioned disk to select the root device
  unambiguously without an initrd.

## Using with the jailer

The jailer does not set up anything VFIO specific. In addition to the
[prerequisites](#prerequisites), the following must be done:

- `/dev/vfio/vfio`, `/dev/vfio/<iommu group>` and the
  `/sys/bus/pci/devices/<sbdf>` directory must be made available inside the
  chroot and be accessible by the jailed `uid`/`gid`.
- `RLIMIT_MEMLOCK` cannot be set with `--resource-limit`. The limit is inherited
  from the process starting the jailer, so it must be raised there (e.g. with
  `prlimit --memlock=<bytes> jailer ...`).

## Security

- **IOMMU is mandatory.** Without an IOMMU, a passthrough device could DMA to
  arbitrary host memory.
- **IOMMU groups.** All devices in the same IOMMU group must be assigned to the
  same VM. Splitting a group across VMs would break DMA isolation. Linux already
  enforces this behaviour.
- **Device reset.** Firecracker resets the device when it is attached and
  removed, but only if the device supports reset (`VFIO_DEVICE_FLAGS_RESET`).
  Devices without reset support can leak state between VMs.

## Snapshot support

VFIO devices do not support snapshots. Device state is opaque to the VMM and
cannot be serialized or restored. VMs with VFIO devices attached cannot be
snapshotted.

## Performance considerations

- All guest memory is pinned and DMA mapped when the first VFIO device is
  attached, either at boot or at the first hot-plug. This time grows with the
  guest memory size and adds to boot or hot-plug latency.
- BAR regions which cannot be mapped directly into the guest are trapped and
  emulated by Firecracker, so each guest access to them causes a VM exit. This
  covers the MSI-X table, BARs the host kernel does not allow to `mmap`, and
  BARs smaller than the host page size.

## Limitations

| Limitation                  | Details                                                                        |
| :-------------------------- | :----------------------------------------------------------------------------- |
| No memory over-subscription | All the memory of the guest will be paged in and pinned by the kernel          |
| No peer-to-peer DMA         | Only guest memory is DMA mapped. Devices cannot DMA into other devices' BARs.  |
| Limited 32-bit BAR space    | Non-prefetchable and 32-bit BARs share a less than 1GiB MMIO window.           |
| No snapshots                | Device state is opaque and cannot be saved/restored.                           |
| Limited BAR relocation      | BARs are relocated one at a time, so swapping BAR addresses does not work.     |
| No BAR resizing             | Resizable BAR capability is masked from the guest.                             |
| No IO BARs                  | IO-type BARs are skipped. Devices relying solely on IO BARs will not work.     |
| No ROM BAR                  | Expansion ROM BAR is not handled.                                              |
| No MSI (non-X)              | Only MSI-X interrupts are supported. Devices without MSI-X fail to initialize. |
| No INTx                     | Legacy pin-based interrupts are not supported.                                 |
| No SR-IOV                   | SR-IOV capability is masked. Virtual Functions cannot be created.              |
| No virtio-iommu             | The guest has no IOMMU. DMA isolation relies entirely on the host IOMMU.       |
| Incompatible devices        | VFIO devices cannot be used together with balloon, virtio-mem or pmem devices. |
