# Memory Hotplugging with virtio-mem

## What is virtio-mem

`virtio-mem` is a para-virtualized memory device that enables dynamic memory
resizing for virtual machines. Unlike traditional memory hotplug mechanisms,
`virtio-mem` provides a flexible and efficient solution that works across
different architectures.

The `virtio-mem` device manages a contiguous memory region that is divided into
fixed-size blocks. The host can request the guest to plug (make available) or
unplug (release) memory by changing the device's target size, and the guest
driver responds by allocating or freeing memory blocks accordingly. This
approach provides fine-grained control over guest memory with minimal overhead.

Firecracker further adds the concept of slots, which are a set of contiguous
blocks (usually 128MiB) that can be fully protected from guest accesses to
prevent malicious guests from accessing the hotpluggable memory range when not
allowed by the host.

## Prerequisites

To support memory hotplugging via `virtio-mem`, you must use a guest kernel with
the appropriate version and configuration options enabled as follows:

#### Kernel Version Requirements

- `x86_64`: minimal kernel version is 5.16
  - Earlier versions of the kernel don't support
    `VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE`
- `aarch64`: minimal kernel version is 5.18

For more information about officially supported guest kernels, refer to the
[kernel policy documentation](kernel-policy.md).

#### Kernel Config

`CONFIG_VIRTIO_MEM` needs to be enabled in the guest kernel in order to use
`virtio-mem`.

## Adding hotpluggable memory

The `virtio-mem` device must be configured during VM setup with the total amount
of memory that can be hotplugged, before starting the virtual machine. This can
be done through a `PUT` request on `/hotplug/memory` or by including the
configuration in the JSON configuration file. In both cases, when the VM is
started, the hotpluggable region will be completely unplugged.

> [!Note] Memory configured through `/hotplug/memory` is a separate pool of
> memory from the usual "boot memory". Only memory configured through the
> hotplug endpoint can be plugged or unplugged dynamically.

### Configuration Parameters

- `total_size_mib` (required): The maximum size of hotpluggable memory in MiB.
  This defines the upper bound of memory that can be added to the VM. Must be a
  multiple of `slot_size_mib`.

- `block_size_mib` (optional, default: 2): The size of individual memory blocks
  in MiB. Must be at least 2 MiB and a power of 2. Larger block sizes provide
  better performance but less granularity (harder for the guest to unplug).

- `slot_size_mib` (optional, default: 128): The size of KVM memory slots in MiB.
  Must be at least `block_size_mib` and a power of 2. Larger slot sizes improve
  performance for large memory operations but reduce unplugging protection
  efficiency.

It is recommended to leave these values to the default unless strict memory
protection is required, in which case `block_size_mib` should be equal to
`slot_size_mib`. Note that this will make it harder for the guest kernel to find
contiguous memory to hot-un-plug. Refer to the
[Memory Protection](#memory-protection) section below for more details.

### API Configuration

Here is an example of how to configure the `virtio-mem` device via the API. In
this example, the hotpluggable memory is configured with a maximum of 1 GiB in
size and default block and slot sizes.

```console
socket_location=/run/firecracker.socket

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/hotplug/memory' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"total_size_mib\": 1024,
        \"block_size_mib\": 2,
        \"slot_size_mib\": 128
    }"
```

> [!Note] This is only allowed before the `InstanceStart` action and not on
> snapshot-restored VMs (which will use the configuration saved in the
> snapshot).

### JSON Configuration

To configure via JSON, add the following to your VM configuration file. In this
example, the hotpluggable memory is configured with a maximum of 1 GiB in size
and default block and slot sizes.

```json
{
    "memory-hotplug": {
        "total_size_mib": 1024,
        "block_size_mib": 2,
        "slot_size_mib": 128
    }
}
```

### Checking Device Status

After configuration, you can query the device status at any time:

```console
socket_location=/run/firecracker.socket

curl --unix-socket $socket_location -i \
    -X GET 'http://localhost/hotplug/memory' \
    -H 'Accept: application/json'
```

This returns information about the current device state, including:

- `total_size_mib`: Maximum hotpluggable memory size
- `block_size_mib`: Block size used by the device
- `slot_size_mib`: Slot size used by Firecracker (granularity of memory
  protection)
- `plugged_size_mib`: Currently plugged (available) memory by the guest
- `requested_size_mib`: Target memory size set by the host

## Operating the virtio-mem device

Once configured and the VM is running, you can dynamically adjust the amount of
memory available to the guest by updating the requested size, which is the
target that the guest should reach by requesting to plug or unplug memory
blocks. The initial value of the requested size is 0 MiB, meaning that no
hotpluggable memory blocks are plugged on VM boot.

### Hotplugging Memory

To add memory to a running VM, request a greater size from the `virtio-mem`
device:

```console
socket_location=/run/firecracker.socket

curl --unix-socket $socket_location -i \
    -X PATCH 'http://localhost/hotplug/memory' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"requested_size_mib\": 512
    }"
```

Setting a higher `requested_size_mib` value causes the guest driver to allocate
memory blocks to reach the requested size. The process is asynchronous -- the
guest will incrementally plug memory until it reaches the target. It is
recommended to use the `GET` API to monitor the current state of the hotplugging
by the driver. The operation is complete when `plugged_memory_mib` is equal to
`requested_memory_mib`.

### Hot-removing Memory

To remove memory from a running VM, request a lower size:

```console
socket_location=/run/firecracker.socket

curl --unix-socket $socket_location -i \
    -X PATCH 'http://localhost/hotplug/memory' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"requested_size_mib\": 256
    }"
```

Setting a lower `requested_size_mib` value causes the guest driver to free
memory blocks. Once the guest reports a block to be unplugged, the unplugged
memory is immediately freed from the host process. If all blocks in a memory
slot are unplugged, then Firecracker will also protect the memory slot, removing
access from the guest.

To remove all hotplugged memory, set `requested_size_mib` to 0:

```console
curl --unix-socket $socket_location -i \
    -X PATCH 'http://localhost/hotplug/memory' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{"requested_size_mib": 0}'
```

> [!Note] Unplugging requires the guest to cooperate and actually be able to
> find and report memory blocks that can be moved or freed by the host. As in
> the hotplugging case, it is recommended to monitor the operation through the
> `GET` API.

## Configuring the guest driver

The guest kernel must be configured with specific boot or runtime module
parameters to ensure optimal behavior of the `virtio-mem` driver and memory
hotplug module.

In short:

- pass `memhp_default_state=online_movable` if hot-removal is required and there
  is enough free boot memory for allocating the memory map of the hotplugged
  memory (64B per 4KiB page).
- pass `memory_hotplug.memmap_on_memory=1 memhp_default_state=online` if
  hot-removal is not required and the hotpluggable memory area can be much
  bigger than the normal memory.

#### `memhp_default_state`

This parameter controls how newly hotplugged memory is onlined by the kernel.
This parameter is required for automatically onlining new memory pages. It is
recommended to set it to `online_movable` as below for reliable memory
hot-removal.

```
memhp_default_state=online_movable
```

The `online_movable` setting ensures that:

- Hotplugged memory is placed in the MOVABLE zone
- The kernel can migrate pages when unplugging is requested
- Memory can be successfully freed back to the host

Other possible values (not recommended for hot-removal):

- `online`: Places memory automatically between NORMAL and MOVABLE zone (may
  prevent hot-remove)
- `online_kernel`: Places memory in NORMAL zone (may prevent hot-remove)
- `offline` (default): Memory requires manual onlining

#### `memory_hotplug.memmap_on_memory` (optional)

This parameter controls whether the kernel allocates memory map (`struct pages`)
for hotplugged memory from the hotplugged memory itself, rather than from boot
memory. Without this parameter, the kernel needs 64B for every 4KiB page in the
boot memory. For example, it would need 262 MiB of free "boot" memory to hotplug
16 GiB of memory. This parameter only works if the memory is not entirely
hotplugged as MOVABLE.

```
memory_hotplug.memmap_on_memory=1 memhp_default_state=online
```

This configuration is recommended in case hot-removal is not a priority, and the
hotpluggable memory area is very large.

#### Additional Resources

For more detailed and up-to-date information about memory hotplug in the Linux
kernel, refer to the official kernel documentation:
https://docs.kernel.org/admin-guide/mm/memory-hotplug.html

## Security Considerations

**The `virtio-mem` device is a paravirtualized device requiring cooperation from
a driver in the guest.**

### Memory Protection

Firecracker provides the following guarantees about unplugged memory:

- **Memory that is never plugged is protected**: Memory that has never been
  plugged before is protected from the guest by not making it available to the
  guest via a KVM slot and by using `mprotect` to prevent access from device
  emulation. Any attempt by the guest to access unplugged memory will result in
  a fault and may crash the Firecracker process.
- **Unplugged memory slots are protected**: Memory slots that have been
  unplugged are removed from KVM and `mprotect`-ed. This requires the guest to
  report contiguous blocks to be freed for the memory slot to be actually
  protected.
- **Unplugged memory blocks are freed**: When a memory block is unplugged, the
  backing pages are freed, for example using `madvise(MADV_DONTNEED)` for anon
  memory, returning memory to the host at block granularity.

### Trust Model

While Firecracker enforces memory isolation at the host level, a compromised
guest driver could:

- Fail to plug or unplug memory as requested by the device
- Attempt to access unplugged memory (will result in a fault and crash of
  Firecracker)

Users should:

- Be prepared to handle cases where the guest doesn't cooperate with memory
  operations by monitoring the `GET` API.
- Implement host-level memory limits and monitoring, e.g. through `cgroup`.

## Compatibility with Other Features

`virtio-mem` is compatible with all Firecracker features. Below are some
specific changes in the other features when using memory hotplugging.

### Snapshots

Full and diff snapshots will include the unplugged areas as sparse "holes" in
the memory snapshot file. Sparse file support is recommended to efficiently
handle the memory snapshot files.

### Userfaultfd

The userfaultfd (uffd) handler[^uffd] will need to handle the entire
hotpluggable memory range even if unplugged. The uffd handler may decide to
unregister unplugged memory ranges (holes in the memory file). The uffd handler
will also need to handle `UFFD_EVENT_REMOVE` events for hot-removed blocks,
either unregistering the range or storing the information and returning an empty
page on the next access.

### Vhost-user

`vhost-user`[^vhost-user] is fully supported, but Firecracker cannot guarantee
protection of unplugged memory from a `vhost-user` backend. A malicious guest
driver may be able to trick the backend to access unplugged memory. This is not
possible in Firecracker itself as unplugged memory slots are `mprotect`-ed.

[^uffd]: snapshotting/handling-page-faults-on-snapshot-resume.md#userfaultfd

[^vhost-user]: api_requests/block-vhost-user.md
