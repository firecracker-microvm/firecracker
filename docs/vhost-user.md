# Using generic vhost-user devices

## What is a vhost-user device

The
[vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)
allows virtio device emulation to be offloaded to a separate backend process
communicating over a Unix domain socket. The backend handles the actual device
logic while Firecracker acts as the frontend, managing virtqueues and guest
memory.

A generic vhost-user frontend knows nothing about the specific virtio device
type being implemented. The backend is fully responsible for the device
configuration space. This allows using device types that Firecracker would never
support natively (e.g. virtio-fs, virtio-scsi) without requiring a dedicated
frontend for each.

## Prerequisites

- The vhost-user backend process must be running and listening on the configured
  Unix domain socket **before** configuring the device in Firecracker.
- The backend must support the `VHOST_USER_PROTOCOL_F_CONFIG` protocol feature,
  as Firecracker relies on the backend to provide the device configuration
  space.
- The guest kernel must include the driver for the virtio device type being
  emulated (e.g. `CONFIG_VIRTIO_FS=y` for virtio-fs).

## Configuration

The following options are available:

- `id` - unique identifier of the device.
- `device_type` - the virtio device type ID as defined in the
  [virtio specification](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1930005).
  For example: `26` for virtio-fs, `8` for virtio-scsi.
- `socket` - path to the vhost-user backend Unix domain socket.
- `num_queues` - number of virtqueues to configure for this device. This must
  match what the backend and the guest driver expect for the device type, and
  must be at least 1. For example, virtio-fs needs one hiprio queue plus at
  least one request queue, so `num_queues` must be 2 or more; configuring fewer
  queues than the guest driver sets up leaves the device unusable.
- `queue_size` (optional) - size of each virtqueue. Defaults to 256.

### Config file

```json
"vhost-user-devices": [
    {
        "id": "fs0",
        "device_type": 26,
        "socket": "/tmp/virtiofsd.sock",
        "num_queues": 2,
        "queue_size": 256
    }
]
```

### API

```console
curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/vhost-user-devices/fs0' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
         \"id\": \"fs0\",
         \"device_type\": 26,
         \"socket\": \"/tmp/virtiofsd.sock\",
         \"num_queues\": 2,
         \"queue_size\": 256
    }"
```

## Example: virtio-fs with virtiofsd

Start the [virtiofsd](https://gitlab.com/virtio-fs/virtiofsd) backend:

```console
virtiofsd \
    --socket-path=/tmp/virtiofsd.sock \
    --shared-dir=/path/to/shared \
    --tag=myfs
```

> [!NOTE]
>
> The `--tag` flag is required to enable the `VHOST_USER_PROTOCOL_F_CONFIG`
> protocol feature in virtiofsd.

Then configure the device in Firecracker as shown above. Inside the guest, mount
the shared directory:

```console
mount -t virtiofs myfs /mnt
```

## Limitations

- **Snapshotting is not supported.** Creating or restoring snapshots of a VM
  with generic vhost-user devices will fail.
- **Configuration space writes are not yet forwarded** to the backend via
  `VHOST_USER_SET_CONFIG`. The protocol supports it, we just haven't wired it
  up: backends such as virtiofsd and SPDK do not rely on guest-initiated config
  writes, so it is deferred, matching the existing vhost-user block device.
- **`num_queues` must match what the backend serves.** The backend's own feature
  bits are offered to the guest, so a guest that accepts a multi-queue feature
  sizes itself from the backend's configuration space, which this frontend
  cannot parse. Configure fewer queues than the backend serves and the guest
  will try to use queues that do not exist; the surplus in the other direction
  is skipped harmlessly.
- **A few feature bits are never offered**, whatever the backend advertises,
  because honouring them is the frontend's job and Firecracker does not
  implement them: packed rings, a platform IOMMU, notification data, per-queue
  reset, an admin queue, SR-IOV, and dirty page logging.
- **`config_space_size` must match the backend's configuration space.** Both the
  vhost-user protocol and Firecracker require the backend to answer with exactly
  as many bytes as were asked for, and a frontend agnostic to the device type
  cannot work out how many that is. It defaults to 256, which suits a backend
  that pads its reply; set it to the device type's own size otherwise, e.g. 44
  for virtio-fs or 60 for virtio-block. Attaching the device fails if the reply
  is a different length.
- **Configuration space changes cannot be pushed to the guest.** The config
  space is read once when the device is attached and there is no API to refresh
  it, so a backend whose configuration changes afterwards has no way to tell the
  guest.
- **The backend must be started before the device is attached.** Firecracker
  connects to the socket when processing the `PUT /vhost-user-devices/{id}`
  request and will return an error if the backend is not available.
