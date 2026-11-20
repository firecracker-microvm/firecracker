# Block device discard

Firecracker can expose virtio-blk discard support to Linux guests. When enabled,
the guest can issue discard/TRIM requests, for example through `fstrim`, and
Firecracker forwards those requests to the backing storage.

Discard is configured per virtio-block device through the `discard` field in the
`PUT /drives/{drive_id}` request. It is disabled by default.

## Supported configuration

Discard is supported for writable virtio-block devices using either IO engine.
It is not supported for:

- read-only drives;
- vhost-user block devices.

How Firecracker executes discard depends on the IO engine and the backend:

- `Sync` engine: hole punching (`fallocate`) for regular files and `BLKDISCARD`
  for block devices.
- `Async` engine: an `IORING_OP_FALLOCATE` hole punch for regular files, and
  `BLOCK_URING_CMD_DISCARD` through `IORING_OP_URING_CMD` for block devices.

`BLOCK_URING_CMD_DISCARD` was added in Linux 6.12, so a block device backend
with `discard` and the `Async` engine requires a host kernel 6.12 or newer. On
older hosts the `PUT /drives` request fails, as does a `PATCH /drives` request
that points such a drive to a block device. Regular file backends work with the
`Async` engine on all supported host kernels.

## Discard alignment and drive updates

Firecracker advertises discard alignment in 512-byte sectors. For a regular
file, the alignment is the advertised
[logical block size](../block.md#logical-block-size). For a raw block device,
Firecracker uses the largest of the advertised logical block size and the
backend's reported logical block size, minimum I/O size, and optimal I/O size.
This applies even when the drive configuration specifies `blk_size` or
`topology`. For example, a thin pool that reports a 64 KiB minimum I/O size can
expose a 64 KiB discard alignment with a 512-byte guest logical block size. The
minimum and optimal I/O sizes are hints. The backend may reclaim smaller ranges.
If Firecracker cannot read the backend attributes, it uses the advertised
logical block size.

For a disk update, the discard alignment required by the new backend must divide
the advertised alignment. Firecracker does not check this requirement, so the
user must provide a compatible backend. Otherwise, the backend can reject a
valid guest request, and Firecracker returns `VIRTIO_BLK_S_IOERR`. For example,
replacing a regular file with alignment `1` by a block file with 4096-byte
logical sectors having alignment `8` is invalid because `1 % 8 != 0`.

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
