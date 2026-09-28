# PCIe device passthrough (VFIO)

Firecracker can assign a physical PCI Express function of the host directly to a
microVM, using the Linux [VFIO](https://docs.kernel.org/driver-api/vfio.html)
framework. This gives the guest direct access to the hardware, typically to use
an accelerator such as a GPU. Any PCIe endpoint that the host can bind to the
`vfio-pci` driver can be assigned.

With passthrough the guest drives the real hardware: the device BARs are mapped
into the guest address space (accesses do not exit to Firecracker), and the
device interrupts are delivered to the guest by KVM without going through
Firecracker. The host IOMMU restricts the device DMA to the guest memory.

Passthrough is built on the PCIe transport, so it requires the `--enable-pci`
flag (see [getting started](getting-started.md)).

## Requirements

- An IOMMU enabled on the host, with interrupt remapping: Intel VT-d or AMD-Vi
  on x86_64, an SMMU on aarch64. Intel hosts usually need `intel_iommu=on` on
  the host kernel command line; AMD-Vi is enabled by default.
- A host kernel with `CONFIG_VFIO`, `CONFIG_VFIO_PCI` and
  `CONFIG_VFIO_IOMMU_TYPE1`.
- A guest kernel with PCI, MSI and, for MSI-X devices, MSI-X support, plus the
  guest driver of the device (for example the NVIDIA driver for an NVIDIA GPU),
  which needs loadable module support when the driver is built as modules.
- Enough locked memory: VFIO pins all guest memory for DMA, and the pinned pages
  count against the `RLIMIT_MEMLOCK` limit of the Firecracker process, unless it
  has `CAP_IPC_LOCK`. The limit must be at least the guest memory size.

## Preparing a device on the host

Find the PCI address of the function and its IOMMU group:

```bash
lspci -nn
# e.g. 01:00.0 VGA compatible controller [0300]: NVIDIA ... [10de:2684]
#      01:00.1 Audio device [0403]: NVIDIA ... [10de:22ba]

ls /sys/bus/pci/devices/0000:01:00.0/iommu_group/devices
# e.g. 0000:00:01.0 0000:00:01.1 0000:01:00.0 0000:01:00.1
```

The IOMMU group is the unit of isolation of the host: the kernel only lets
userspace use a group when every endpoint in it is bound to `vfio-pci` (or to no
driver); PCI bridges in the group may keep their driver. Bind every endpoint of
the group to `vfio-pci`, not only the one to assign:

```bash
for dev in 0000:01:00.0 0000:01:00.1; do
    echo vfio-pci > /sys/bus/pci/devices/$dev/driver_override
    echo $dev > /sys/bus/pci/devices/$dev/driver/unbind
    echo $dev > /sys/bus/pci/drivers_probe
done
```

The group is then usable through `/dev/vfio/<group>` and `/dev/vfio/vfio`. Only
the functions listed in the microVM configuration are assigned to the guest; the
other endpoints of the group stay bound to `vfio-pci` and unused. Functions of
the same IOMMU group can be assigned to the same microVM, but a group can only
be used by one microVM at a time.

## Assigning the device to a microVM

Passthrough devices are configured before the microVM starts. A device is
referenced by the path of its sysfs directory.

Using the API:

```bash
curl --unix-socket "${API_SOCKET}" -i \
    -X PUT 'http://localhost/vfio/gpu0' \
    -H 'Content-Type: application/json' \
    -d '{
        "id": "gpu0",
        "path": "/sys/bus/pci/devices/0000:01:00.0"
    }'
```

Using a JSON configuration file (`--config-file`), add a `vfio` array:

```json
{
  "vfio": [
    {
      "id": "gpu0",
      "path": "/sys/bus/pci/devices/0000:01:00.0"
    }
  ]
}
```

In the guest, each assigned function shows up as a single-function PCIe endpoint
on bus 0, and the matching guest driver binds to it.

### Running with the jailer

A jailed Firecracker needs, inside its chroot, the VFIO device nodes and the
`iommu_group` link of each assigned device, and a locked memory limit covering
the guest memory. The [jailer](jailer.md) sets these up with `--vfio-device`,
which takes the same sysfs path as the Firecracker configuration and can be
repeated, and with `--resource-limit memlock=<bytes>`:

```bash
jailer --id vm0 --exec-file /usr/bin/firecracker --uid 123 --gid 100 \
    --vfio-device /sys/bus/pci/devices/0000:01:00.0 \
    --resource-limit memlock=$((4 << 30)) \
    -- --enable-pci --api-sock /run/firecracker.socket
```

The jailer recreates `/dev/vfio/vfio`, the `/dev/vfio/<group>` node of each
group and the `iommu_group` link of each device (with the same target as on the
host); nothing else of the host sysfs is exposed.

## How it works

- **IOMMU context.** All devices of a microVM share one VFIO container, that is
  one IOMMU address space, in which all guest memory is mapped with I/O virtual
  addresses equal to guest physical addresses. Firecracker checks the guest
  memory layout against the address ranges the host IOMMU accepts before mapping
  it. The groups are registered with KVM through the KVM-VFIO device.
- **Reset.** vfio-pci resets a device when Firecracker opens it, if the kernel
  has a reset method scoped to that function. For a device without such a
  method, Firecracker performs a PCI hot reset when every device the reset would
  affect belongs to the microVM; otherwise the device is assigned without reset
  and a warning is logged.
- **Configuration space** accesses go to the device through vfio-pci, which
  filters what the guest may change. Firecracker emulates the registers whose
  guest view must differ from the host: the BARs and the expansion ROM BAR
  (guest addresses), the header type (the multi-function bit is cleared), the
  interrupt pin and line, the MSI capability and the MSI-X message control
  register. The SR-IOV, ARI and Resizable BAR extended capabilities are removed
  from the capability list: they describe host functions and host BAR sizes that
  the guest cannot use.
- **BARs** are placed in the guest MMIO windows, largest first from the top of
  each window. The parts of a BAR that the host allows to be mapped are mapped
  directly into the guest, at host addresses aligned like the guest addresses so
  that KVM can use huge pages. The pages of the MSI-X table and pending bit
  array, and the parts that cannot be mapped (for example BARs smaller than a
  page), are trapped and forwarded to the device. The expansion ROM is exposed
  read-only. When the guest disables memory decoding or puts the device in
  D3hot, the BARs are removed from the guest address space: accesses then read
  all ones, as on bare metal. BARs the guest moved while decoding was disabled
  are relocated when it is enabled again.
- **Interrupts.** MSI (including multiple messages) and MSI-X are emulated: each
  vector is routed by vfio-pci to an eventfd that KVM injects into the guest
  with the message address and data the guest programmed. Masking a vector keeps
  its interrupt pending until it is unmasked, and the pending bits read by the
  guest reflect it. Host vectors are allocated as the guest enables and unmasks
  them. A function with an interrupt pin has INTA in the guest (some drivers
  need it even to use MSI, such as the NVIDIA driver for GPUs without MSI-X),
  routed level-triggered to an interrupt controller input: an IOAPIC input from
  16 up on x86_64, described in the ACPI PCI routing table and in the MP table,
  and a GIC SPI on aarch64, described in the device tree. vfio-pci signals it to
  an eventfd that KVM injects, and the guest's end of interrupt unmasks it on
  the host, as for a level-triggered line. INTx is routed while the guest has
  neither MSI nor MSI-X enabled. When there are more such functions than free
  inputs, they share inputs, as on physical platforms.

## Limitations

- Passthrough requires `--enable-pci`, and devices can only be configured before
  boot: hot-plugging and hot-unplugging are not supported.
- A microVM with a passthrough device cannot be
  [snapshotted](snapshotting/snapshot-support.md): the device state lives in the
  hardware and cannot be saved.
- The [balloon device](ballooning.md) and [memory hotplug](memory-hotplug.md)
  cannot be used together with passthrough, and the microVM does not start with
  such a configuration: both give guest memory back to the host while the device
  may still access it through the IOMMU mappings.
- Guest memory backing [virtio-pmem](pmem.md) devices is not mapped in the
  IOMMU: the assigned device cannot DMA to or from it.
- I/O BARs are not exposed, and neither is VGA legacy memory.
- Starting a microVM pins all its guest memory for device DMA, which takes time
  proportional to the guest memory size. Backing the guest memory with
  [huge pages](hugepages.md) makes it faster.
- BARs cannot be resized by the guest. The guest can relocate them, as it can
  for every Firecracker PCI device: an address written to a BAR or to the
  expansion ROM BAR takes effect when the BAR next starts decoding memory, if
  the new range is free and lies in a device MMIO window that can hold the BAR
  (see below). Otherwise the BAR keeps its address, and its register reads that
  address back.
- Each BAR is naturally aligned. The 64-bit prefetchable BARs share the 256 GiB
  64-bit MMIO window, which the guest sees as prefetchable, and the guest can
  also move them to the 32-bit MMIO window. The other BARs, 64-bit
  non-prefetchable ones included, and the expansion ROM share the 32-bit MMIO
  window (about 750 MiB) with the virtio-pci devices, which take 512 KiB each.
  When the BARs do not fit, the microVM does not start. When the passthrough
  BARs leave no room in the 32-bit window for a virtio-pci device, that device
  cannot be added, and its hotplug request fails.
- The guest memory must lie in I/O virtual address ranges the host IOMMU accepts
  (for example, AMD hosts reserve 1012-1024 GiB); Firecracker refuses to start
  otherwise.
