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
a memory mapped file on the host side and is exposed to the guest kernel as an
region in the guest physical memory. This allows the guest to directly access
the host memory pages without a need to use guest driver or interact with VMM.
From guest user-space perspective `virtio-pmem` devices are presented as normal
block device like `/dev/pmem0`. This allows `virtio-pmem` to be used as rootfs
device and make VM boot from it.

> [!NOTE]
>
> Since `virtio-pmem` is located fully in memory, when used as a block device
> there is no need to use guest page cache for it's operations. This behaviour
> can be configured by using `DAX` feature of the kernel.
>
> - To mount a device with `DAX` add `--flags=dax` to the `mount` command.
> - To configure a root device with `DAX` append `rootflags=dax` to the kernel
>   arguments.
>
> `DAX` support is not uniform for all file systems. Check the documentation for
> the file system you want to use before enabling `DAX`.

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
> with sequential names in the for `/dev/pmem{N}` like: `/dev/pmem0`,
> `/dev/pmem1` ...

> [!WARNING]
>
> Setting `virtio-pmem` device to `read-only` mode can lead to VM shutting down
> on any attempt to write to the device. This is because from guest kernel
> perspective `virtio-pmem` is always `read-write` capable. Use `read-only` mode
> only if you want to ensure the underlying file is never written to.
>
> The exact behaviour differs per platform:
>
> - x86_64 - if KVM is able to decode the write instruction used by the guest,
>   it will return a MMIO_WRITE to the Firecracker where it will be discarded
>   and the warning log will be printed.
> - aarch64 - the instruction emulation is much stricter, so writes will in
>   internal KVM error which will be returned to Firecracker in a for of ENOSYS
>   return value from `KVM_RUN`. This will make Firecracker stop the VM with
>   appropriate log message.

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
      "read_only": fasle
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
