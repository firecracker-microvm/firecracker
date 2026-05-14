# Device Hotplugging [Developer Preview]

> [!WARNING]
>
> This feature is currently in
> [Developer Preview](RELEASE_POLICY.md#developer-preview-features). It may have
> limitations, and its API or behavior may change in future releases.

Device hotplugging allows attaching and detaching PCI virtio devices to a
running microVM without requiring a reboot. Supported device types are:

- `virtio-block`
- `virtio-pmem`
- `virtio-net`

## Prerequisites

- **PCI transport enabled**: Firecracker must be started with the `--enable-pci`
  flag. Device hotplugging is not supported with MMIO transport.
- **Guest kernel with PCI support**: The guest kernel must have PCI and the
  relevant virtio drivers enabled. See the
  [kernel policy documentation](kernel-policy.md) for details.

## Limitations

- **No automatic guest notification**: Firecracker does not currently deliver a
  hotplug notification to the guest. After hotplugging a device, the guest must
  manually rescan the PCI bus to discover it. Similarly, before unplugging, the
  guest must manually remove the device.

## Hotplugging a device

Hotplugging uses the same API endpoints used for pre-boot device configuration.
The only difference is that the request is issued after the VM has started.

```console
socket_location=/run/firecracker.socket

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/drives/block1' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
        "drive_id": "block1",
        "path_on_host": "/path/to/block.ext4",
        "is_root_device": false,
        "is_read_only": false
    }'
```

### Discovering the device in the guest

Since no hotplug notification is delivered to the guest, a PCI bus rescan is
required to make the guest discover the new device:

```bash
echo 1 > /sys/bus/pci/rescan
```

After the rescan, the device will appear in `lspci` and the corresponding device
node (e.g. `/dev/vdb`, `/dev/pmem1`) will be created by the guest kernel.

## Hot-unplugging a device

Hot-unplugging is a two-step process: first the guest must release the device,
then the host issues the unplug request.

### Step 1: Remove the device from the guest

Before issuing the unplug API call, the guest must gracefully release the
device. For example, unmount any mounted filesystems and remove the PCI device:

```bash
# Unmount the filesystem (if applicable)
umount /mnt/block1

# Remove the device from the guest
echo 1 > /sys/bus/pci/devices/0000:00:01.0/remove
```

Replace `0000:00:01.0` with the actual PCI BDF (Bus:Device.Function) address of
the device, which can be found via `lspci`.

### Step 2: Unplug from the host

Issue a `DELETE` request to the corresponding device endpoint:

```console
curl --unix-socket $socket_location -i \
    -X DELETE 'http://localhost/drives/block1'
```
