# VFIO Device Passthrough

> [!WARNING]
>
> This feature is currently in
> [Developer Preview](RELEASE_POLICY.md#developer-preview-features). It may have
> limitations, and its API or behavior may change in future releases.

## What is VFIO

VFIO (Virtual Function I/O) is a Linux kernel framework that allows userspace
programs to directly access physical devices in a secure, IOMMU-protected
environment. Firecracker uses VFIO to pass through PCI devices from the host
into the guest, giving the guest near-native performance access to physical
hardware such as GPUs, network adapters, and NVMe drives.

## Prerequisites

VFIO passthrough requires:

- Firecracker must be started with the `--enable-pci` flag since VFIO devices
  are PCI devices.
- An IOMMU (Intel VT-d, AMD-Vi, or ARM SMMU) must be enabled on the host.
- The host must have the `vfio` and `vfio-pci` kernel modules loaded.
- The target PCI device must be unbound from its native kernel driver and bound
  to the `vfio-pci` driver.
- All devices in the same IOMMU group must be bound to `vfio-pci`.

## How to bind device to `vfio-pci` driver

To bind a device (e.g. `0000:01:02.03`) to `vfio-pci`:

```bash
# Unbind from current driver
echo "0000:01:02.03" > /sys/bus/pci/devices/0000:01:02.03/driver/unbind
# Bind to vfio-pci
echo "vfio-pci" > /sys/bus/pci/devices/0000:01:02.03/driver_override
echo "0000:01:02.03" > /sys/bus/pci/drivers/vfio-pci/bind
```

## Configuration

Firecracker exposes the following configuration options for VFIO devices:

- `id` - unique identifier for the device
- `sbdf` - host PCI device identifier, accepted in many forms:
  - full SBDF: `0000:01:02.03`
  - short BDF: `01:02.03`

### Config file

```json
"vfio": [
    {
      "id": "device0",
      "sbdf": "0000:01:02.03"
    }
]
```

### API

#### Add device

The same `PUT /vfio/{id}` endpoint works only before the VM boot:

```console
curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/vfio/device0' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
         \"id\": \"device0\",
         \"sbdf\": \"0000:01:02.03\"
    }"
```

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

## Security

- **IOMMU is mandatory.** Without an IOMMU, a passthrough device could DMA to
  arbitrary host memory.
- **IOMMU groups.** All devices in the same IOMMU group must be assigned to the
  same VM. Splitting a group across VMs would break DMA isolation. Linux already
  enforces this behaviour.

## Snapshot support

VFIO devices do not support snapshots. Device state is opaque to the VMM and
cannot be serialized or restored. VMs with VFIO devices attached cannot be
snapshotted.

## Limitations

| Limitation                  | Details                                                                        |
| :-------------------------- | :----------------------------------------------------------------------------- |
| No memory over-subscription | All the memory of the guest will be paged in and pinned by the kernel          |
| No snapshots                | Device state is opaque and cannot be saved/restored.                           |
| No BAR relocation           | BAR addresses are assigned at init and cannot be moved.                        |
| No BAR resizing             | Resizable BAR capability is masked from the guest.                             |
| No IO BARs                  | IO-type BARs are skipped. Devices relying solely on IO BARs will not work.     |
| No ROM BAR                  | Expansion ROM BAR is not handled.                                              |
| No MSI (non-X)              | Only MSI-X interrupts are supported. Devices without MSI-X fail to initialize. |
| No INTx                     | Legacy pin-based interrupts are not supported.                                 |
| No SR-IOV                   | SR-IOV capability is masked. Virtual Functions cannot be created.              |
| No virtio-iommu             | The guest has no IOMMU. DMA isolation relies entirely on the host IOMMU.       |
