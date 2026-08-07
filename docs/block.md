# Using the Firecracker Virtio-block Device

### Kernel config

- Guest kernel config has: `CONFIG_VIRTIO_BLK=y`

To confirm that the block device is exposed to the guest, run the following
inside the guest:

```bash
ls /sys/class/block/
```

and confirm that a `vd<x>` entry (e.g. `vda`, `vdb`) exists for each drive
attached to the microVM.

Example guest kernel configuration that Firecracker uses in its CI can be found
[here](../resources/guest_configs/).

## Firecracker Virtio-block

Firecracker implements the
[virtio-blk device model](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-2740002)
as defined by the VirtIO specification. Each drive is backed by a file (or a
block device) on the host and exposed to the guest as a `/dev/vd<x>` device.

Drives are attached before the microVM boots via the `/drives/{drive_id}` API
endpoint or configured through the config file. The first drive marked as
`is_root_device` becomes `/dev/vda` in the guest; the remaining drives appear in
the order they were configured.

Host IO is performed either synchronously (via blocking `read`/`write`/`fsync`
system calls) or asynchronously (via `io_uring`). The engine is selectable per
drive; see [IO Engine](#io-engine).

## Setting up the Virtio-block Device

A drive requires at minimum a `drive_id`, a `path_on_host` and the
`is_root_device` flag:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/drives/rootfs' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
      "drive_id": "rootfs",
      "path_on_host": "./rootfs.ext4",
      "is_root_device": true,
      "is_read_only": false
  }'
```

The equivalent block in a JSON configuration file will look like this:

```json
"drives": [
    {
        "drive_id": "rootfs",
        "path_on_host": "./rootfs.ext4",
        "is_root_device": true,
        "is_read_only": false
    }
]
```

The `path_on_host` must be readable (and writable, when `is_read_only` is
`false`) by the Firecracker process.

## Configuration Options

### Caching Strategy

The `cache_type` field on a drive controls whether guest flush requests are
honoured by the host. Two values are accepted:

- `Unsafe` (default) — the device does not advertise `VIRTIO_BLK_F_FLUSH`. Guest
  flushes are ignored.
- `Writeback` — the device advertises `VIRTIO_BLK_F_FLUSH`. Each guest flush
  translates into an `fsync` on the backing file.

See [block-caching.md](api_requests/block-caching.md) for more information.

### IO Engine

The `io_engine` field selects the host-side IO backend:

- `Sync` (default) — blocking `read`/`write` syscalls.
- `Async` — `io_uring`-based, supports multiple in-flight requests. Requires
  host kernel >= 5.10.51. Currently in **developer preview**.

See [block-io-engine.md](api_requests/block-io-engine.md) for more information.

### Read-only Devices

Setting `is_read_only` to `true` causes Firecracker to open the backing file
`O_RDONLY` and tell the guest to mark the device as read-only as well.

### Rate Limiting

The optional `rate_limiter` field caps IO bandwidth and/or request rate:

```json
"rate_limiter": {
    "bandwidth": {
        "size": 1048576,
        "one_time_burst": 0,
        "refill_time": 1000
    },
    "ops": {
        "size": 500,
        "one_time_burst": 0,
        "refill_time": 1000
    }
}
```

`bandwidth` limits bytes/s; `ops` limits requests/s. `size` is the bucket
capacity, `refill_time` the refill interval in milliseconds, `one_time_burst` a
one-shot allowance available at boot.

### Logical Block Size

Firecracker always enables the `VIRTIO_BLK_F_BLK_SIZE` feature which allows the
user to configure the logical block size. The value used in the configuration is
picked in the following order:

1. If the user set the optional `blk_size` field on the drive, that value is
   used.
1. Otherwise, if the backing file is a **host block device** and **no
   [topology](#block-topology) is set**, Firecracker queries the kernel for its
   logical sector size and uses that value instead.
1. Otherwise Firecracker uses default of **512 bytes**, which matches the
   virtio-blk default.

Users can override the default with the optional `blk_size` field on the drive:

```json
"blk_size": 4096
```

The value must be a positive power of two and within a range acceptable to the
kernel (typically [512..4096]). The guest kernel will check this value during
device initialization. Advertising a larger logical block size (e.g. `4096`)
forces the guest to submit all reads and writes aligned to that size.

> [!NOTE]
>
> `blk_size` is also the unit in which every field of the
> [Block Topology](#block-topology) config is expressed. Changing this value
> changes how the guest scales `physical_block_exp`, `min_io_size` and
> `opt_io_size` — see the next section.

### Block Topology

Firecracker always advertises the `VIRTIO_BLK_F_TOPOLOGY` feature to the guest.
All four topology fields are on the wire in units of the
[logical block size](#logical-block-size) (`blk_size`, 512 B by default). The
guest kernel then computes:

- `physical_block_size = blk_size << physical_block_exp`
- `minimum_io_size     = blk_size * min_io_size`
- `optimal_io_size     = blk_size * opt_io_size`

and exposes those values under `/sys/block/vd<x>/queue/`.

#### How topology values are chosen

The values placed in the config space are picked in the following order:

1. If the user set the optional `topology` field on the drive (see below), those
   values are used.
1. Otherwise, if the backing file is a **host block device** and **no
   [blk_size](#logical-block-size) is set**, Firecracker derives
   `physical_block_exp`, `min_io_size` and `opt_io_size` from the kernel. Each
   byte value is divided by the device's logical sector size to convert bytes
   into wire units. `alignment_offset` is always reported as `0`.
1. Otherwise (regular file, or obtaining values from the kernel fails)
   Firecracker falls back to a fixed set of defaults, described next.

#### Default values

Values below assume the default `blk_size` of 512 B; the byte figures scale with
`blk_size` if it is overridden.

```
physical_block_exp: 0    # guest will default to physical size of 512
alignment_offset:   0
min_io_size:        0    # guest keeps its own default (no hint)
opt_io_size:        128  # 128 *  512 B  = 64 KiB optimal I/O
```

#### Overriding via configuration

Users can overwrite the defaults by setting the optional `topology` field:

```json
"topology": {
    "physical_block_exp": 3,
    "alignment_offset": 0,
    "min_io_size": 8,
    "opt_io_size": 128
}
```

> [!NOTE]
>
> Specifying values as `0` makes the guest use its own defaults

#### Deriving values from a host block device

For a block-device backing this reproduces what Firecracker computes
automatically; the same math is useful when configuring `topology` by hand for a
file-backed drive that should mirror a particular disk. Values can be read from
the host `/sys/block/<name>/queue/` directory; `alignment_offset` will be at the
top level of the block device (`/sys/block/<name>/alignment_offset`):

| Sysfs path (bytes)                    | Topology field       | Wire units (`blk_size` blocks)          |
| ------------------------------------- | -------------------- | --------------------------------------- |
| `queue/logical_block_size`            | -                    | -                                       |
| `queue/physical_block_size`           | `physical_block_exp` | `log2(physical / logical)`              |
| `queue/minimum_io_size`               | `min_io_size`        | `minimum_io_size / logical_block_size`  |
| `queue/optimal_io_size`               | `opt_io_size`        | `optimal_io_size / logical_block_size`  |
| `alignment_offset` (device top-level) | `alignment_offset`   | `alignment_offset / logical_block_size` |

For example, if the backing device is `/dev/nvme0n1`:

```console
# for attr in queue/logical_block_size queue/physical_block_size \
              queue/minimum_io_size    queue/optimal_io_size    \
              alignment_offset; do
      printf '%-30s %s\n' "$attr" "$(cat /sys/block/nvme0n1/$attr)"
  done
queue/logical_block_size       512
queue/physical_block_size      4096
queue/minimum_io_size          4096
queue/optimal_io_size          65536
alignment_offset               0
```

These values can be converted to the `topology` options:

```json
"topology": {
    "physical_block_exp": 3,
    "alignment_offset": 0,
    "min_io_size": 8,
    "opt_io_size": 128
}
```

> [!NOTE]
>
> If **either** `blk_size` or `topology` options are set during configuration,
> the automatic deduction of these values from the kernel is not performed. This
> is done to remove ambiguity when these options are configured.

## Updating a Drive at Runtime

A `PATCH /drives/{drive_id}` request can change the `path_on_host` and/or
`rate_limiter` of an existing virtio drive. See
[patch-block.md](api_requests/patch-block.md) for more information.

> [!NOTE]
>
> Patching block device does not change already configured `blk_size` or
> `topology` fileds.

## Examples

### Root device from a file

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/rootfs" \
     -H "Content-Type: application/json" \
     -d '{
         "drive_id": "rootfs",
         "path_on_host": "./rootfs.ext4",
         "is_root_device": true,
         "is_read_only": false
     }'
```

### Read-only scratch drive with `Writeback` caching and `Async` engine

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/scratch" \
     -H "Content-Type: application/json" \
     -d '{
         "drive_id": "scratch",
         "path_on_host": "./dummy.ext4",
         "is_root_device": false,
         "is_read_only": true,
         "cache_type": "Writeback",
         "io_engine": "Async"
     }'
```

### Drive with a 1 MiB/s bandwidth cap and 500 ops/s

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/throttled" \
     -H "Content-Type: application/json" \
     -d '{
         "drive_id": "throttled",
         "path_on_host": "./dummy.ext4",
         "is_root_device": false,
         "is_read_only": false,
         "rate_limiter": {
             "bandwidth": { "size": 1048576, "one_time_burst": 0, "refill_time": 1000 },
             "ops":       { "size": 500,     "one_time_burst": 0, "refill_time": 1000 }
         }
     }'
```

### Drive with custom topology values

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/data" \
     -H "Content-Type: application/json" \
     -d '{
         "drive_id": "data",
         "path_on_host": "./dummy.ext4",
         "is_root_device": false,
         "is_read_only": false,
         "topology": {
             "physical_block_exp": 3,
             "alignment_offset": 0,
             "min_io_size": 8,
             "opt_io_size": 128
         }
     }'
```

### Booting from a PARTUUID

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/rootfs" \
     -H "Content-Type: application/json" \
     -d '{
         "drive_id": "rootfs",
         "path_on_host": "./disk.img",
         "is_root_device": true,
         "is_read_only": false,
         "partuuid": "0eaa91a0-01"
     }'
```

The guest's kernel command line must reference `root=PARTUUID=<value>`.

## Known Limitations

- The `Async` IO engine is in [developer preview](RELEASE_POLICY.md) — see the
  [threat sections](api_requests/block-io-engine.md#developer-preview-status)
  before enabling it in production.
- The guest-visible capacity is snapshotted at boot from `stat` on the backing
  file. Extending the file on the host does not grow the guest device until the
  drive is patched (see
  [Updating a Drive at Runtime](#updating-a-drive-at-runtime)).
