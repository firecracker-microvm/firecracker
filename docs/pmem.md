# Using the Firecracker `virtio-pmem` device

## What is a persistent memory device

Persistent memory is a type of non-volatile, CPU accessible (with usual
load/store instructions) memory that does not lose its content on power loss. In
other words all writes to the memory persist over the power cycle. In hardware
this known as NVDIMM memory (Non Volatile Double Inline Memory Module).

## What is a `virtio-pmem` device:

[`virtio-pmem`](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-68900019)
is a device which emulates a persistent memory device without requiring a
physical NVDIMM device be present on the host system. `virtio-pmem` is backed by
a memory mapped file on the host side and is exposed to the guest kernel as a
region in the guest physical memory. This allows the guest to directly access
the host memory pages without a need to use guest driver or interact with VMM.
From guest user-space perspective `virtio-pmem` devices are presented as normal
block device like `/dev/pmem0`. This allows `virtio-pmem` to be used as rootfs
device and make VM boot from it.

> [!NOTE]
>
> Since `virtio-pmem` is located fully in memory, when used as a block device
> there is no need to use guest page cache for its operations. This behaviour
> can be configured by using `DAX` feature of the kernel.
>
> - To mount a device with `DAX` add `--flags=dax` to the `mount` command.
> - To configure a root device with `DAX` append `rootflags=dax` to the kernel
>   arguments.
>
> `DAX` support is not uniform for all file systems. Check the kernel
> [documentation](https://github.com/torvalds/linux/blob/master/Documentation/filesystems/dax.rst)
> for more information.

## Prerequisites

In order to use `virtio-pmem` device, guest kernel needs to built with support
for it. The full list of configuration options needed for `virtio-pmem` and
`DAX`:

```
# Needed for DAX on aarch64. Will be ignored on x86_64
CONFIG_ARM64_PMEM=y

CONFIG_DEVICE_MIGRATION=y
CONFIG_ZONE_DEVICE=y
CONFIG_VIRTIO_PMEM=y
CONFIG_LIBNVDIMM=y
CONFIG_BLK_DEV_PMEM=y
CONFIG_ND_CLAIM=y
CONFIG_ND_BTT=y
CONFIG_BTT=y
CONFIG_ND_PFN=y
CONFIG_NVDIMM_PFN=y
CONFIG_NVDIMM_DAX=y
CONFIG_OF_PMEM=y
CONFIG_NVDIMM_KEYS=y
CONFIG_DAX=y
CONFIG_DEV_DAX=y
CONFIG_DEV_DAX_PMEM=y
CONFIG_DEV_DAX_KMEM=y
CONFIG_FS_DAX=y
CONFIG_FS_DAX_PMD=y
```

## Configuration

Firecracker implementation exposes these config options for the `virtio-pmem`
device:

- `id` - id of the device for internal use
- `path_on_host` - path to the backing file
- `root_device` - toggle to use this device as root device. Device will be
  marked as `rw` in the kernel arguments
- `read_only` - tells Firecracker to `mmap` the backing file in read-only mode.
  If this device is also configured as `root_device`, it will be marked as `ro`
  in the kernel arguments

> [!NOTE]
>
> Devices will be exposed to the guest in the order in which they are configured
> with sequential names in the form of `/dev/pmem{N}` like: `/dev/pmem0`,
> `/dev/pmem1` ...

> [!WARNING]
>
> Setting `virtio-pmem` device to `read-only` mode can lead to VM shutting down
> on any attempt to write to the device. This is because from guest kernel
> perspective `virtio-pmem` is always `read-write` capable. Use `read-only` mode
> only if you want to ensure the underlying file is never written to.
>
> To mount the `pmem` device with `read-only` options add `-o ro` to the `mount`
> command.
>
> The exact behaviour differs per platform:
>
> - x86_64 - if KVM is able to decode the write instruction used by the guest,
>   it will return a MMIO_WRITE to the Firecracker where it will be discarded
>   and the warning log will be printed.
> - aarch64 - the instruction emulation is much stricter. Writes will result in
>   an internal KVM error which will be returned to Firecracker in a form of an
>   `ENOSYS` error. This will make Firecracker stop the VM with appropriate log
>   message.

> [!WARNING]
>
> `virtio-pmem` requires for the guest exposed memory region to be 2MB aligned.
> This requirement is transitively carried to the backing file of the
> `virtio-pmem`. Firecracker allows users to configure `virtio-pmem` with
> backing file of any size and fills the memory gap between the end of the file
> and the 2MB boundary with empty `PRIVATE | ANONYMOUS` memory pages. Users must
> be careful to not write to this memory gap since it will not be synchronized
> with backing file. This is not an issue if `virtio-pmem` is configured in
> `read-only` mode.

### Config file

Configuration of the `virtio-pmem` device from config file follows similar
pattern to `virtio-block` section. Here is an example configuration for a single
`virtio-pmem` device:

```json
"pmem": [
    {
      "id": "pmem0",
      "path_on_host": "./some_file",
      "root_device": true,
      "read_only": false
    }
]
```

### API

Similar to other devices `virtio-pmem` can be configured with API calls. An
example of configuration request:

```console
curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/pmem/pmem0' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
         \"id\": \"pmem0\",
         \"path_on_host\": \"./some_file\",
         \"root_device\": true,
         \"read_only\": false
    }"
```

## Security

It is not recommended to use the same backing file for `virtio-pmem` across
different VMs, as this causes the same physical pages to be mapped to different
VMs, which could be exploited as a side channel by an attacker inside the
microVM. Users that want to use `virtio-pmem` to share memory are encouraged to
carefully evaluate the security risk according to their threat model.

## Snapshot support

`virtio-pmem` works with snapshot functionality of Firecracker. Snapshot will
contain the configuration options provided by the user. During restoration
process, Firecracker will attempt to restore `virtio-pmem` device by opening
same backing file as it was configured in the first place. This means all
`virtio-pmem` backing files should be present in the same locations during
restore as they were during initial `virtio-pmem` configuration.

## Performance

Even though `virtio-pmem` allows for the direct access of host pages from the
guest, the performance of the first access of each page will suffer from the
internal KVM page fault which will have to set up Guest physical address to Host
Virtual address translation. Consecutive accesses will not need to go through
this process again.

Since the number of page faults correlate to the size of the pages used to back
`virtio-pmem` memory, it is possible to use huge pages to reduce number of
required page fault. This can be done by using
[`tmpfs`](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html) with
transparent huge pages enabled or by using
[`hugetblfs`](https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html)
if `virtio-pmem` is used for memory sharing.

## Memory usage

> [!NOTE] `virtio-pmem` memory can be paged out by the host, because it is
> backed by a file with `MAP_SHARED` mapping type. To prevent this from
> happening, you can use `vmtouch` or similar tool to lock file pages from being
> evicted.

`virtio-pmem` resides in host memory and does increase the maximum possible
memory usage of a VM since now VM can use all of its RAM and access all of the
`virtio-pmem` memory. In order to minimize the overhead, it is highly
recommended to use `DAX` mode to avoid unnecessary duplication of data in guest
page cache.

As an example, a single VM with 128MB of memory booted from `virtio-pmem` device
without `DAX` has `RSS` value of ~120MB, while with `DAX` it is ~96MB. The ~96MB
is similar to memory usage of a VM booted using `virtio-block` as a root device.

In the case where multiple VMs have `virtio-pmem` devices that point to the same
underlying file the memory overhead can be amortized since total maximum memory
usage will only include a single instance of `virtio-pmem` memory.

As an example 2 VMs configured with 128MB of RAM without `virtio-pmem` devices
can consume maximum of 128 + 128 = 256MB of host memory. If each of VMs will
have a 100MB `virtio-pmem` device attached with shared backing file, the maximum
memory consumption will be 128 + 128 + 100 = 356MB because 100MB of
`virtio-pmem` will be shared between VMs.
