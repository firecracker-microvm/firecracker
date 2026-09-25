# Getting started with Nitro Sandboxes

This document describes what the parent instance and the guest kernel need to
run a Nitro Sandbox, with two worked examples. For the concepts behind any of
this, see [How it works](how-it-works.md).

## Requirements

### Parent instance

Nitro Sandboxes run on the
[instance types that support AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-reqs).
Both x86_64 (Intel and AMD) and aarch64 (AWS Graviton) instances are supported.
Unlike KVM microVMs, sandboxes do not run on bare-metal instances.

Launch the instance with Nitro Enclaves enabled. The example uses the latest
Amazon Linux 2023 AMI with kernel 6.18, which has the parent kernel support
described below; on AWS Graviton, use `al2023-ami-kernel-6.18-arm64` instead:

```bash
aws ec2 run-instances \
  --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.18-x86_64 \
  --instance-type <instance-type> \
  --enclave-options 'Enabled=true'
```

For more details, see the
[Amazon EC2 User Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nitro-sandboxes.html#nitro-sandboxes-launch).

### Parent kernel

The parent kernel needs Nitro Sandboxes support in its `nitro_enclaves` driver.
The required patches are in the Amazon Linux 2023 `kernel6.18` kernel from
version `6.18.51-120.162.amzn2023`. The AMI in the launch example above meets
this.

Check that the driver is loaded:

```console
$ ls -la /dev/nitro_enclaves
crw-rw----. 1 root root 10, 258 Sep  3 15:44 /dev/nitro_enclaves
```

Firecracker must be able to open that device. The jailer creates the device node
inside the chroot and grants the jailed user access to it; for details, see
[Jailer](features.md#jailer).

### CPU and memory pools

Two pools back sandbox launches: the CPU pool and the memory pool. Each has a
directory under `/sys/class/misc/nitro_enclaves/`, `cpu_pool/` and `mem_pool/`,
with `total`, `in_use` and `free` counters and a per-node breakdown:

```console
$ cd /sys/class/misc/nitro_enclaves
$ cat cpu_pool/total cpu_pool/in_use          # here on a 32-vCPU parent
30
0
$ echo $(( $(cat mem_pool/free) / 1048576 ))  # MiB left in the reserved pool
49974
```

- **CPU pool.** Dedicated-core sandboxes draw whole cores from here. By default
  (`nitro_enclaves.ne_cpus=dynamic`) the driver builds the pool on demand from
  every core except CPU 0's. To fix the pool instead, set
  `nitro_enclaves.ne_cpus=<cpu-list>`, listing both SMT siblings of every core
  and leaving out CPU 0's core. Sandboxes with `cpu_overcommit` do not touch
  this pool.
- **Memory pool.** Donated memory comes from physically contiguous memory the
  driver reserves, accounted per NUMA node. Reserve a pool at boot with the
  `nitro_enclaves.mempool=` kernel parameter, which takes absolute sizes,
  percentages of a node's memory, and per-node placement, for example
  `nitro_enclaves.mempool=4G`, `=50%`, or `=4G@0,4G@1`. Without a reservation
  the driver allocates contiguous memory from general parent memory on each
  launch; a reservation makes the allocation deterministic and is what the
  `mem_pool/` counters report.

### Slot budget

Besides the CPU and memory pools, the slot budget bounds how many sandboxes the
parent can hold at once. Each sandbox occupies one slot from creation until it
exits; the driver calls them PCIe slots. A freshly booted parent starts with a
base budget of 4, before any memory is donated. Raise it by writing a target to
`pcie_slots`:

```bash
echo 68 | sudo tee /sys/class/misc/nitro_enclaves/pcie_slots
```

Each increase donates parent memory to the Nitro System in 128 MiB chunks of 8
slots each, taken from the same memory pool as sandbox RAM, so the budget grows
in steps of 8 and `pcie_slots` can read back higher than the value written. The
memory stays donated until the parent reboots. On a parent with several NUMA
nodes the donations are spread across the nodes and slots are accounted per
node.

Three files under `/sys/class/misc/nitro_enclaves/` report the parent's slot
state, here on a 32-vCPU instance after the write above:

```console
$ cd /sys/class/misc/nitro_enclaves
$ cat pcie_slots_total    # most sandboxes this instance can ever hold
160
$ cat pcie_slots          # sandboxes the parent can currently hold
68
$ cat pcie_slots_in_use   # sandboxes currently holding a slot
2
```

`pcie_slots` can only grow: a write fails with `EINVAL` if it exceeds
`pcie_slots_total` or is lower than the current value, and with `ENOMEM` if the
memory pool cannot supply the donation. The total vCPUs of all the sandboxes on
a parent are limited too; for that limit, see
[Sandboxes per instance](comparison-with-kvm.md#sandboxes-per-instance).

### Guest kernel

The Amazon Linux 2023 `kernel6.18` kernels that carry the parent-side support,
from `6.18.51-120.162.amzn2023`, also work as guest kernels, DMB patches
included. Firecracker's CI guest kernels carry the DMB patches too. Any other
distribution kernel works, provided it has:

- **ACPI and PCIe support.** The Nitro System gives the guest ACPI tables and a
  PCIe topology, and the guest enumerates devices the ordinary way. The microVM
  kernel configs used for KVM microVMs work as long as ACPI and virtio-pci are
  enabled.
- **An EFI-bootable image**, because a sandbox boots through UEFI firmware. On
  x86_64 that means an EFI-stub `bzImage` (`CONFIG_EFI_STUB=y`); the `vmlinux`
  images used for KVM microVMs cannot boot a sandbox. On aarch64 the kernel
  `Image` boots via EFI when built with `CONFIG_EFI_STUB=y`, the default.
- **virtio-pci drivers** for the attached devices: `CONFIG_VIRTIO_PCI`,
  `CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_NET`, `CONFIG_VIRTIO_VSOCKETS` and so on.
- **`CONFIG_HOTPLUG_PCI_PCIE=y`**, to notice hotplugged devices.
- **The DMB virtio patches, for confidential mode only.** They let the guest's
  virtio driver keep a device's virtqueues in its Device Memory Buffer instead
  of in guest RAM; for what a DMB is, see
  [Confidential mode](how-it-works.md#confidential-mode-default). DMB is a
  proposed virtio extension, `VIRTIO_F_DMB`; for its design, see the
  [specification proposal](https://lore.kernel.org/all/20260818060255.6853-1-graf@amazon.com/)
  and the
  [Linux driver series](https://lore.kernel.org/all/20260818211425.91009-1-graf@amazon.com/).
  Direct mode works with unpatched virtio drivers.
- **`CONFIG_NSM=y`, if the workload uses attestation.** The driver exposes
  `/dev/nsm`. The NSM device is present in every confidential sandbox whether or
  not the guest has the driver.

#### Getting a guest kernel for testing

The quickest way is the CI kernel and Ubuntu rootfs from
[Getting a rootfs and Guest Kernel Image](../getting-started.md#getting-a-rootfs-and-guest-kernel-image).
On aarch64 those commands work unchanged, because the `vmlinux-` artifact is
already an EFI-bootable `Image`. On x86_64, replace `vmlinux-` with `bzImage-`
in the two kernel download lines and in the `KERNEL=$(ls vmlinux-* ...)` check
at the end, to fetch the EFI-stub image.

For a custom guest kernel, Firecracker's CI kernels are a working reference,
with the DMB patches available in `resources/patches/dmb/`. For how to build a
guest kernel and root filesystem, see
[Creating Custom rootfs and kernel Images](../rootfs-and-kernel-setup.md).

## Boot images

A sandbox boots from an EIF, which comes from one of two places:

- **Let Firecracker build it.** When attestation is not required, point
  `kernel_image_path` at an EFI-bootable kernel image, optionally with
  `initrd_path` and `boot_args`, and Firecracker assembles an EIF in memory at
  start time. This is what the examples below use.

- **Supply a pre-built EIF.** Point `kernel_image_path` at an `.eif` file
  instead. Firecracker detects it by its magic bytes and boots it as-is, so
  `boot_args` and `initrd_path` are ignored: those are baked into the image, and
  they are part of what its measurements cover. Firecracker also adds nothing to
  the image's command line, so the default and the automatic arguments described
  below apply only when Firecracker builds the EIF.

  The image must also be built for the configuration it runs under. Its header
  declares a set of capability flags, and they must match the flags Firecracker
  derives from the enclave configuration exactly: `cpu_overcommit`,
  `cpu_accounting`, `hotplug_mode` and a multi-node `numa_nodes` each set one.
  An image built for a different configuration fails at `InstanceStart`; for why
  the match is strict, see [Booting](how-it-works.md#booting).

When Firecracker builds the EIF and `boot_args` is not set, the default command
line is:

```
panic=1 initcall_blacklist=i8042_init
```

Whether or not `boot_args` is set, Firecracker then appends:

- `console=ttyS0`, in debug mode, unless a `console=` argument is already
  present.
- `root=/dev/vda` (or `root=PARTUUID=...`) and `rw` or `ro`, derived from the
  drive configured with `is_root_device: true`. This is appended even if
  `boot_args` already contains a `root=` argument, and comes after it, so the
  kernel uses the appended one.

These arguments become part of the EIF's command line, and so of its
measurements: changing which drive is the root device, its PARTUUID or its
read-only flag changes the PCRs.

`initcall_blacklist=i8042_init` skips the PS/2 controller probe to speed up
boot, since a sandbox has no PS/2 device. A guest kernel built without the i8042
driver does not need it.

## Example: boot from a configuration file

The whole sandbox can be described in the JSON file passed to `--config-file`,
with the sandbox settings under an `enclave` key. Apart from the EFI-bootable
kernel, the `enclave` key is the only change from a KVM microVM configuration.

```json
{
    "boot-source": {
        "kernel_image_path": "/path/to/bzImage"
    },
    "machine-config": {
        "vcpu_count": 2,
        "mem_size_mib": 512
    },
    "drives": [
        {
            "drive_id": "rootfs",
            "path_on_host": "/path/to/rootfs.ext4",
            "is_root_device": true,
            "is_read_only": false
        }
    ],
    "network-interfaces": [
        {
            "iface_id": "eth0",
            "guest_mac": "06:00:AC:10:00:02",
            "host_dev_name": "tap0"
        }
    ],
    "enclave": {
        "debug_mode": true,
        "cpu_overcommit": true
    }
}
```

```bash
firecracker --api-sock /tmp/fc.sock --config-file /path/to/vm_config.json
```

Set up `tap0` on the parent first, exactly as for any microVM; for how, see
[Network setup](../network-setup.md). Confidential mode is the default here,
since `direct_mode` is absent, so the guest kernel needs the DMB virtio patches.
`cpu_overcommit` lets the sandbox run without taking cores from the CPU pool.

`debug_mode` turns on the serial console, and in confidential mode zeroes the
attestation PCRs, so a confidential sandbox started with it cannot attest its
image.

## Example: boot through the API

This example configures the same devices request by request, this time in direct
mode with dedicated cores, so an unpatched guest kernel boots. With dedicated
cores `vcpu_count` must be even on a parent with SMT.

```bash
# Start Firecracker
firecracker --api-sock /tmp/fc.sock

# In another terminal:
# 1. Machine config
curl -X PUT http://localhost/machine-config \
  --unix-socket /tmp/fc.sock \
  -d '{
    "vcpu_count": 2,
    "mem_size_mib": 512
  }'

# 2. Boot source
curl -X PUT http://localhost/boot-source \
  --unix-socket /tmp/fc.sock \
  -d '{
    "kernel_image_path": "/path/to/bzImage"
  }'

# 3. Root filesystem
curl -X PUT http://localhost/drives/rootfs \
  --unix-socket /tmp/fc.sock \
  -d '{
    "drive_id": "rootfs",
    "path_on_host": "/path/to/rootfs.ext4",
    "is_root_device": true,
    "is_read_only": false
  }'

# 4. Network interface
curl -X PUT http://localhost/network-interfaces/eth0 \
  --unix-socket /tmp/fc.sock \
  -d '{
    "iface_id": "eth0",
    "guest_mac": "06:00:AC:10:00:02",
    "host_dev_name": "tap0"
  }'

# 5. Sandbox config. Direct mode shown; omit direct_mode for confidential.
curl -X PUT http://localhost/enclave \
  --unix-socket /tmp/fc.sock \
  -d '{
    "debug_mode": true,
    "direct_mode": true
  }'

# 6. Start
curl -X PUT http://localhost/actions \
  --unix-socket /tmp/fc.sock \
  -d '{"action_type": "InstanceStart"}'
```

`root=/dev/vda rw` is derived from the root drive, so no `boot_args` are needed.

After boot the guest is reachable over the TAP network like any other microVM.
The MAC address follows the convention of the Ubuntu rootfs from
[Getting Started](../getting-started.md), whose `fcnet-setup.sh` derives the
guest address 172.16.0.2 from it. With `tap0` set up as 172.16.0.1, log in with
the key created there:

```bash
ssh -i ./ubuntu-*.id_rsa root@172.16.0.2
```

With `debug_mode` the boot log appears on Firecracker's standard output, here
the first terminal. To send it to a file instead, add `PUT /serial` before
starting; for the request, see [Serial console](features.md#serial-console).

## Troubleshooting

### `/dev/nitro_enclaves` not found

The instance was not launched with `--enclave-options 'Enabled=true'`, or the
parent kernel has no Nitro Enclaves driver.

### `Failed to open /dev/nitro_enclaves: Permission denied`

The user running Firecracker has no access to the device node. Check its owner
and group with `ls -l /dev/nitro_enclaves`.

### `Failed to query hypervisor-supported flags` at start

The parent kernel's Nitro Enclaves driver predates Nitro Sandboxes, and the
error ends in `Inappropriate ioctl for device (os error 25)`. Use the Amazon
Linux 2023 `kernel6.18` package `6.18.51-120.162.amzn2023` or later.

### `Hypervisor does not support required matched flags` at start

The driver supports sandboxes, but the platform does not advertise every
capability the configuration asks for. Check that the instance type supports
Nitro Enclaves and was launched with them enabled. The `missing=` mask names the
flags that are missing.

### `A Nitro Enclave does not support ...` at start

The configuration asks for something the sandbox path does not implement, and
the message names it. Machine-config fields that fail this way are `huge_pages`,
`smt`, `cpu_template`, `track_dirty_pages` and `pcie_hotplug_ports`, and in
builds with GDB support `gdb_socket_path`; leave them unset. A CPU template set
through `PUT /cpu-config` fails the same way. Devices that fail this way are the
balloon, pmem, memory hotplug and vhost-user block, none of which has a sandbox
transport:

```console
{"fault_message":"Start microvm error: Enclave builder error: A Nitro Enclave does not support huge_pages"}
```

### `NE_ERR_FULL_CORES_NOT_USED (errno=269)`

A dedicated-core sandbox asked for a vCPU count that is not a whole number of
cores, typically an odd count on a parent with SMT. Use an even `vcpu_count`, or
enable `cpu_overcommit`, where any count is allowed.

### CPU pool errors

The pool holds whole cores only. When configuring a static pool, include both
SMT siblings of each core:

```bash
cat /sys/devices/system/cpu/cpu1/topology/thread_siblings_list
```

A launch can also fail because too few cores are free, with
`NE_ERR_NO_CPUS_AVAIL_IN_POOL (errno=272): no CPUs are available in the NE CPU pool`.
`cpu_pool/free` reports how many remain. A sandbox started with `cpu_overcommit`
does not draw from this pool at all.

### Memory allocation failures

Donated memory must be physically contiguous and is accounted per node, so a
launch can fail on the requested node while another node still has room. Check
the per-node counters under `/sys/class/misc/nitro_enclaves/mem_pool/`, and size
the reservation with `nitro_enclaves.mempool=`. Every sandbox also takes a 2 MiB
control page from the pool, through which the Nitro System reports device state,
and in confidential mode its DMBs, 16 MiB per device by default; both land on
the lowest-numbered node of its placement.

### No slots left

Each sandbox occupies a slot, and there are three ways to run out of them.

- `pcie_slots_in_use` has reached `pcie_slots_total`, the most sandboxes the
  instance can hold. `InstanceStart` fails with `errno=553`, the per-instance
  limit, and writing to `pcie_slots` does not help.
- The slot budget is used up while it could still grow. `InstanceStart` fails
  with an error ending in
  `Failed to create enclave VM: No space left on device (os error 28)`. A
  freshly booted parent is in this state after 4 sandboxes. Raise the budget by
  writing to `pcie_slots`.
- On a parent with several NUMA nodes, the node the sandbox's vCPUs land on has
  no slot memory left. `InstanceStart` fails with
  `NE_ERR_NO_MEM_SLOTS_ON_NODE (errno=554): the per-NUMA-node memory budget is exhausted`.
  Raise the budget further, since donations are spread across the nodes in turn,
  or place the sandbox on another node.

Compare `pcie_slots_in_use`, `pcie_slots` and `pcie_slots_total` under
`/sys/class/misc/nitro_enclaves/` to see which applies; for what each file
reports, see [Slot budget](#slot-budget). The total vCPU limit in
[Sandboxes per instance](comparison-with-kvm.md#sandboxes-per-instance) is
separate from the slot budget and applies as well.

### `NE_ADD_DEVICE ioctl failed: Invalid argument (os error 22)` when adding a device

Most commonly the sandbox already holds 32 devices, the per-sandbox ceiling. The
parent's kernel log then has a line starting with
`NE_ADD_DEVICE rejected: enclave has 32 devices, max 32`.

### `dmb_size_mib cannot be set in direct mode`

A device sets `dmb_size_mib` on a direct-mode sandbox, which allocates no DMBs.
Remove the field from the device, or run the sandbox in confidential mode.

### Entropy device rejected at start

`InstanceStart` fails with `NE_ERR_DEVICE_DISALLOWED` when a confidential
sandbox has an entropy device, because the Nitro System disallows virtio-rng
there. `PUT /entropy` itself succeeds. Remove the entropy device and rely on the
guest's own entropy sources, or use direct mode if the workload does not need
protection from the parent.

### The guest boots but SSH times out

- Check that the root drive has `is_root_device: true`, so `root=` points at the
  right device, and that drives are configured in the intended order, with the
  root device first as `/dev/vda`.
- Check that the rootfs starts `sshd` on boot.
- Check the TAP device and routing on the parent; for the setup, see
  [Network setup](../network-setup.md).
- Boot with `debug_mode` and capture the console with `PUT /serial` to see how
  far the guest gets.

### The guest hangs waiting for its disk or network in confidential mode

The guest kernel lacks the DMB virtio patches, so its virtqueues sit in memory
the parent cannot reach and I/O never completes. Use a guest kernel with the DMB
virtio patches, or use direct mode.

A guest driver that does not negotiate `VIRTIO_F_IOMMU_PLATFORM` at all is
refused outright, and Firecracker logs
`Device uid=<N> did not negotiate VIRTIO_F_IOMMU_PLATFORM while its DMA targets a DMB; not activating`
followed by the negotiated features.
