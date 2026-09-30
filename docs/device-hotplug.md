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
- **PCIe hot-plug ports configured**: `pcie_hotplug_ports` must be set in the
  machine configuration. It defaults to 0, which disables hotplugging.
- **Guest kernel with PCI and PCIe hot-plug support**: The guest kernel must
  have PCI and the native PCI Express hot-plug driver (`pciehp`) enabled
  (`CONFIG_HOTPLUG_PCI=y`, `CONFIG_HOTPLUG_PCI_PCIE=y`, `CONFIG_PCIEPORTBUS=y`).

## How it works

Firecracker puts a number of PCI Express root ports on the root bus, each with
one hot-plug capable slot. A hotplugged device goes into a free slot, and the
root port raises a native PCI Express hot-plug interrupt. The guest's `pciehp`
driver handles it and binds or unbinds the device by itself. Each root port
occupies one slot on the root bus and starts one secondary bus, which is where
its device appears.

## Reserving hot-plug ports

Ports are reserved at boot through the `pcie_hotplug_ports` machine
configuration option, which is the maximum number of devices that can be
hotplugged at any one time. It cannot be changed after boot.

```console
socket_location=/run/firecracker.socket

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/machine-config' \
    -H 'Content-Type: application/json' \
    -d '{
        "vcpu_count": 2,
        "mem_size_mib": 1024,
        "pcie_hotplug_ports": 4
    }'
```

There's a slight boot time overhead for each root port added due to the
additional bus enumeration by the guest (this does not affect snapshot restore).
It is recommended that you only reserve the number of ports needed. The maximum
is 31.

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

Firecracker sends a notification to the guest and the guest discovers the new
device.

## Hotplugging latency

Linux waits for 120 ms after receiving a hotplug notification. This is due to
delays mandated by the PCIe specification. That means that the device will show
up in the guest in a bit more than 120 ms.

If this latency is unacceptable for your use case one workaround is triggering a
manual bus rescan from inside the guest:

```console
echo 1 > /sys/bus/pci/rescan
```

## Making a boot device removable

A device configured before boot normally sits on the root bus and cannot be
unplugged. Setting `removable` on it puts it in a root port slot instead so that
it can be hot-unplugged later. The option exists only for the device types that
can be actually unplugged.

```console
curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/drives/scratch' \
    -H 'Content-Type: application/json' \
    -d '{
        "drive_id": "scratch",
        "path_on_host": "/path/to/scratch.ext4",
        "is_root_device": false,
        "is_read_only": false,
        "removable": true
    }'
```

Each removable device consumes one of the ports reserved by
`pcie_hotplug_ports`.

## Hot-unplugging a device

Only devices behind root ports can be unplugged. Issue a `DELETE` request to the
device's endpoint:

```console
curl --unix-socket $socket_location -i \
    -X DELETE 'http://localhost/drives/block1'
```

This starts a *graceful* removal. Firecracker asks the guest to release the
device and the call returns immediately. The guest's `pciehp` driver then
quiesces the device and powers the slot off at which point Firecracker frees the
backing resources. Linux waits five seconds before releasing the device.

You can poll `GET /vm/config` to find out when the device has actually gone.

### Forcing a removal

If the guest does not respond, `force` removes the device immediately without
waiting:

```console
curl --unix-socket $socket_location -i \
    -X DELETE 'http://localhost/drives/block1' \
    -H 'Content-Type: application/json' \
    -d '{ "force": true }'
```

This might have unpredictable consequences for the guest.
