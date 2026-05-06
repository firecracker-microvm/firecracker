# Block device discard (TRIM)

Firecracker supports the `VIRTIO_BLK_F_DISCARD` feature, which allows the guest
to issue discard (TRIM) requests to the block device. Discard requests tell the
host that a range of sectors is no longer needed, enabling the host to reclaim
space on sparse or thin-provisioned backing files.

## How it works

For all non-read-only block devices, Firecracker automatically advertises the
`VIRTIO_BLK_F_DISCARD` feature to the guest driver. No API configuration is
required — discard support is always-on for writable drives.

When the guest driver issues a `VIRTIO_BLK_T_DISCARD` request, Firecracker calls
`fallocate(2)` with `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE` on the backing
file for each discard segment. This punches a hole in the file, freeing the
underlying disk blocks without changing the file size.

Guest tools that trigger discard include:

- `fstrim -v /` — manually trim a mounted filesystem
- `discard` mount option — automatic discard on file deletion
- `blkdiscard /dev/vda` — discard the entire block device

## Host requirements

The backing file must reside on a filesystem and kernel that support
`FALLOC_FL_PUNCH_HOLE`. This is supported on ext4, xfs, btrfs, and tmpfs on
Linux 3.5+. On filesystems that do not support hole-punching, `fallocate`
returns `EOPNOTSUPP`. Firecracker detects this on the first discard, logs a
one-time warning, and replies to the guest with `VIRTIO_BLK_S_UNSUPP`. The Linux
virtio-blk driver propagates `VIRTIO_BLK_S_UNSUPP` through the block layer and
stops issuing further discard requests. Firecracker short-circuits any remaining
discard requests with `VIRTIO_BLK_S_UNSUPP` immediately — no additional
`fallocate` calls are made.

## Limitations

- Discard is only available for non-read-only block devices.
- At most one discard segment per request is supported (`max_discard_seg = 1`).
- The discard segment flags field must be zero; non-zero flags are rejected with
  an I/O error.
