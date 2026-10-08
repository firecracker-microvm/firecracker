# Block device discard

Firecracker can expose virtio-blk discard support to Linux guests. When enabled,
the guest can issue discard/TRIM requests, for example through `fstrim`, and
Firecracker forwards those requests to the backing storage.

Discard is configured per virtio-block device through the `discard` field in the
`PUT /drives/{drive_id}` request. It is disabled by default.

## Supported configuration

Discard is currently supported only for writable virtio-block devices using the
`Sync` IO engine. It is not supported for:

- read-only drives;
- `Async` IO engine drives;
- vhost-user block devices.

For regular backing files, Firecracker uses hole punching. For block-device
backends, Firecracker uses `BLKDISCARD`.

## Discard alignment and drive updates

The discard alignment is measured in 512-byte sectors. Firecracker sets it to
the advertised [logical block size](../block.md#logical-block-size) divided by
the 512-byte sector size.

For a disk update, the new backend discard alignment must divide the advertised
alignment. Firecracker does not check this requirement, so the user must provide
a compatible backend. Otherwise, the backend can reject a valid guest request,
and Firecracker returns `VIRTIO_BLK_S_IOERR`. For example, replacing a regular
file with alignment `1` by a block file with 4096-byte logical sectors having
alignment `8` is invalid because `1 % 8 != 0`.

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
             \"discard\": true,
             \"io_engine\": \"Sync\"
         }"
```

After the guest boots, Linux guests can usually issue discard requests with:

```bash
fstrim -av
```
