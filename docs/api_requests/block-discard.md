# Block device discard

Firecracker can expose virtio-blk discard support to Linux guests. When enabled,
the guest can issue discard/TRIM requests, for example through `fstrim`, and
Firecracker forwards those requests to the backing storage.

Discard is configured per virtio-block device through the `discard` field in the
`PUT /drives/{drive_id}` request. It is disabled by default.

## Supported configuration

Discard is currently supported only for writable virtio-block devices. It is not
supported for:

- read-only drives;
- vhost-user block devices.

For regular backing files, Firecracker uses hole punching. For block-device
backends, Firecracker uses `BLKDISCARD` with the `Sync` IO engine and
`BLOCK_URING_CMD_DISCARD` with the `Async` IO engine.

When discard is enabled with the `Async` IO engine, regular backing files
require host support for `IORING_OP_FALLOCATE`. Block-device backing stores
additionally require host support for `BLOCK_URING_CMD_DISCARD`, which is
available starting with Linux 6.12.

## Example configuration

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/rootfs" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"rootfs\",
             \"path_on_host\": \"${drive_path}\",
             \"is_root_device\": true,
             \"is_read_only\": false,
             \"io_engine\": \"Async\",
             \"discard\": true
         }"
```

After the guest boots, Linux guests can usually issue discard requests with:

```bash
fstrim -av
```
