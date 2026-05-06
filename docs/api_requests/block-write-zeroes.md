# Block device write-zeroes

Firecracker supports the `VIRTIO_BLK_F_WRITE_ZEROES` feature, which allows the
guest to ask the device to zero a range of sectors without transferring a buffer
of zeros over the virtqueue. Common consumers are `mkfs` (clearing inode tables
and journals), filesystem snapshots, encrypted-volume initial wipe, and
`blkdiscard -z` / `blkzeroout` from userspace.

## How it works

For all non-read-only block devices, Firecracker automatically advertises the
`VIRTIO_BLK_F_WRITE_ZEROES` feature to the guest driver. No API configuration
is required — write-zeroes support is always-on for writable drives.

Each `VIRTIO_BLK_T_WRITE_ZEROES` request carries a 16-byte segment with a
`flags` field. Bit 0 (`VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP`) tells the device
whether it may also deallocate the underlying backing-file blocks. Firecracker
advertises `write_zeroes_may_unmap=1`, so guests are free to set this flag.

Firecracker translates the guest's UNMAP bit into a `fallocate(2)` mode on the
backing file:

| UNMAP | fallocate mode                              | Effect                                |
|-------|---------------------------------------------|---------------------------------------|
| 0     | `FALLOC_FL_ZERO_RANGE \| FALLOC_FL_KEEP_SIZE` | zeros in place, no deallocation     |
| 1     | `FALLOC_FL_PUNCH_HOLE \| FALLOC_FL_KEEP_SIZE` | zeros + deallocate (sparse holes)   |

The virtio spec requires that when UNMAP is clear the device MUST NOT
deallocate sectors (so `ZERO_RANGE` is mandatory for that path); when UNMAP
is set, the device MAY deallocate, and `PUNCH_HOLE` reads as zeros on every
filesystem that supports it.

## Host requirements

The backing file must reside on a filesystem that supports the corresponding
`fallocate` mode:

- `FALLOC_FL_PUNCH_HOLE` (UNMAP=1) is widely supported: ext4, xfs, btrfs, tmpfs.
- `FALLOC_FL_ZERO_RANGE` (UNMAP=0) is supported on ext4, xfs, btrfs; on tmpfs
  it requires Linux 6.8+. Other filesystems may not support it.

If `fallocate` returns `EOPNOTSUPP` for either mode, Firecracker logs a one-time
warning and replies with `VIRTIO_BLK_S_UNSUPP`. The Linux virtio-blk driver
propagates that status through the block layer and stops issuing further
write-zeroes requests, so subsequent guest writes fall back to plain
`REQ_OP_WRITE` traffic. Firecracker short-circuits any in-flight write-zeroes
requests with `VIRTIO_BLK_S_UNSUPP` for the rest of the device's lifetime — no
additional `fallocate` calls are made.

The EOPNOTSUPP cache is shared across UNMAP=0 and UNMAP=1 paths: a single
fallback flag disables both. This is conservative — a filesystem that
supports `PUNCH_HOLE` but not `ZERO_RANGE` will see UNMAP=1 requests rejected
once an UNMAP=0 request fails — but it matches the discard fallback design
and avoids subtle host-side state.

## Limitations

- Write-zeroes is only available for non-read-only block devices.
- At most one segment per request is supported (`max_write_zeroes_seg = 1`).
- Only bit 0 (UNMAP) of the segment flags is allowed; non-zero reserved bits
  are rejected with an I/O error.
