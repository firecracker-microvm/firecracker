# Using generic vhost-user devices

## What is a vhost-user device

The [vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)
allows virtio device emulation to be offloaded to a separate backend
process communicating over a Unix domain socket. The backend handles the
actual device logic while Firecracker acts as the frontend, managing
virtqueues and guest memory.

A generic vhost-user frontend knows nothing about the specific virtio
device type being implemented. The backend is fully responsible for the
device configuration space. This allows using device types that
Firecracker would never support natively (e.g. virtio-fs, virtio-scsi)
without requiring a dedicated frontend for each.

## Prerequisites

- The vhost-user backend process must be running and listening on the
  configured Unix domain socket **before** configuring the device in
  Firecracker.
- The backend must support the `VHOST_USER_PROTOCOL_F_CONFIG` protocol
  feature, as Firecracker relies on the backend to provide the device
  configuration space.
- The guest kernel must include the driver for the virtio device type
  being emulated (e.g. `CONFIG_VIRTIO_FS=y` for virtio-fs).

## Configuration

The following options are available:

- `id` - unique identifier of the device.
- `device_type` - the virtio device type ID as defined in the
  [virtio specification](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1930005).
  For example: `26` for virtio-fs, `8` for virtio-scsi.
- `socket` - path to the vhost-user backend Unix domain socket.
- `num_queues` - number of virtqueues to configure for this device.
- `queue_size` (optional) - size of each virtqueue. Defaults to 256.

### Config file

```json
"vhost-user-devices": [
    {
        "id": "fs0",
        "device_type": 26,
        "socket": "/tmp/virtiofsd.sock",
        "num_queues": 1,
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
         \"num_queues\": 1,
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

Then configure the device in Firecracker as shown above. Inside the
guest, mount the shared directory:

```console
mount -t virtiofs myfs /mnt
```

## Limitations

- **Snapshotting is not supported.** Creating or restoring snapshots of
  a VM with generic vhost-user devices will fail.
- **Configuration space writes are not yet forwarded** to the backend
  via `VHOST_USER_SET_CONFIG`.
- **The backend must be started before the device is attached.**
  Firecracker connects to the socket when processing the
  `PUT /vhost-user-devices/{id}` request and will return an error if the
  backend is not available.
