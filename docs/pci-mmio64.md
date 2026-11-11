# PCI MMIO64 configuration

On x86_64 and aarch64, configure the PCI MMIO64 aperture before boot through
`PUT /machine-config`, `PATCH /machine-config`, or `machine-config` in
`--config-file`. Requires `--enable-pci`.

Example: a 2 TiB aperture at 2 TiB for eight 128 GiB GPU BAR1 regions:

```json
{
  "vcpu_count": 2,
  "mem_size_mib": 4096,
  "pci_mmio64": {
    "base_gib": 2048,
    "size_gib": 2048
  }
}
```

The aperture reserves guest address space; RAM skips it. BAR allocation, x86_64
ACPI and aarch64 device tree ranges use the same bounds. The following 512 GiB
pool serves pmem and memory hotplug; RAM within it is reserved against device
allocations.

Values are integers in GiB. Defaults: base 256, size 256. The base must be at
least 4 and size positive. Size for BARs, alignment and bridge windows;
Firecracker does not size the aperture automatically.

The aperture and following pool must fit within 52 address bits. All mapped
memory must fit KVM and guest CPU address widths, checked after CPU templates.
On aarch64, KVM uses the host IPA width, or 40 bits on legacy hosts. The example
requires at least 43 bits, including the following pool.

Unrelated PATCH requests preserve the aperture. Set both values to 256 to reset
it before boot. Snapshot restore uses saved allocator bounds; load a snapshot in
a fresh process before configuring boot resources. The snapshot format is
unchanged.

GPU assignment requires separate passthrough support.
