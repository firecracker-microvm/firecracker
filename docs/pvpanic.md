# Using the Firecracker pvpanic device

## What is the pvpanic device

The pvpanic device is a paravirtualized device (originally provided by QEMU)
that lets a guest kernel report panic events to the host. When the guest kernel
panics, its `pvpanic` driver writes an event byte to the device's MMIO register;
Firecracker observes that write and can react to it.

## Firecracker implementation

Firecracker implements the pvpanic device as a small MMIO register (a single
byte at offset 0 of a 4 KiB page), matching the [QEMU pvpanic specification][1]
and the Linux [`drivers/misc/pvpanic`][2] driver. It is **not** a VirtIO device
and is **not** configured through the REST API; like the boot timer, it is
enabled on demand via a command-line flag.

To enable the pvpanic device, start Firecracker with the `--enable-pvpanic`
flag:

```console
./firecracker --no-api --enable-pvpanic --config-file <vm-config.json>
```

or, when using the API socket:

```console
./firecracker --enable-pvpanic --api-sock /tmp/firecracker.socket
```

The flag is process-wide: it applies to the microVM booted from that Firecracker
process. There is no per-VM API endpoint to toggle it.

### Device discovery

The guest kernel's pvpanic driver binds to the device:

- on **x86_64**, Firecracker exposes an ACPI device with `_HID = QEMU0001` and a
  memory `_CRS` pointing at the device's MMIO page;
- on **aarch64**, Firecracker adds a device-tree node with
  `compatible = "qemu,pvpanic-mmio"` and a `reg` property.

On Linux 5.15 and newer, at probe time the driver reads the register to learn
which events the device supports, and keeps only the intersection with what it
knows. When the guest panics, the driver (registered at the highest
panic-notifier priority, before a `panic=1` reboot) writes back exactly one
event:

- `PVPANIC_PANICKED` (bit 0) normally;
- `PVPANIC_CRASH_LOADED` (bit 1) if the guest has a crash kernel armed
  (`kdump`), meaning it will dump itself and the host must only record the event
  without disturbing the guest.

Firecracker advertises both. This matters: the driver picks one of the two and
silently drops the notification if that event is not advertised, without falling
back to the other one. A host that advertised only bit 0 would receive nothing
at all from a guest with `kdump` armed.

`PVPANIC_SHUTDOWN` (bit 2), which newer guest kernels use to report a regular
power-off, is deliberately **not** advertised. Advertising it makes the guest
route its power-off through this device and rely on the host to actually
terminate the VM; Firecracker does not do that, so the guest would neither power
off nor fall back to halting.

## Prerequisites

The guest kernel must be built with the pvpanic driver. On Linux 5.15 and newer
it is selected through two Kconfig symbols:

- `CONFIG_PVPANIC=y` (base pvpanic support)
- `CONFIG_PVPANIC_MMIO=y` (the MMIO platform driver; depends on `HAS_IOMEM` and
  `(ACPI || OF)`)

On Linux 5.10 there is only `CONFIG_PVPANIC=y`. That single symbol already
builds the MMIO and device-tree support; `CONFIG_PVPANIC_MMIO` does not exist
yet.

The options should be compiled in (`=y`, not as a module) so the driver is
available in the minimal guest rootfs/initramfs without an explicit module load.
The Firecracker CI guest kernel configs under `resources/guest_configs/` enable
them.

### Guest kernels older than 5.15

Linux 5.15 moved the driver to `drivers/misc/pvpanic/` and reworked it. On older
kernels (for example the 5.10 CI guest kernels) the device still works and
Firecracker still logs the event, but:

- the driver **never reads** the register. It ignores the advertised event mask
  entirely and always writes `PVPANIC_PANICKED`, or `PVPANIC_CRASH_LOADED` if a
  crash kernel is armed;
- it exposes no `capability`/`events` sysfs attributes, so the negotiated event
  set cannot be inspected from inside the guest;
- `PVPANIC_SHUTDOWN` does not exist yet;
- it registers either the platform driver or an ACPI driver, not both: with ACPI
  enabled (x86_64) the device binds to an ACPI driver and does **not** appear
  under `/sys/bus/platform/drivers/pvpanic-mmio/`. On aarch64, where Firecracker
  describes the device through the device tree and ACPI is disabled, it does.

## Current behavior

A `PVPANIC_PANICKED` write is recorded and then handed over to the Firecracker
event loop through an eventfd. The VMM does not act on it yet (for example, it
will not shut the microVM down). The log lines look like:

```text
pvpanic: guest panicked (event=0x1)
pvpanic: guest panic handed over to the VMM
pvpanic: guest panicked and is handling the crash itself (event=0x2)
```

The register write handler runs on the vCPU thread that took the MMIO exit, so
it must not do more than record the event and signal that eventfd: pausing the
vCPUs from there would make the vCPU wait for itself. Anything heavier --
pausing the vCPUs, dumping guest state, stopping the VM -- belongs on the VMM
thread, which is what the notification is for. No interrupt is wired up for the
device.

A `PVPANIC_CRASH_LOADED` write is deliberately **not** handed over and stays
log-only, because the specification requires the host not to affect the
execution of a guest that is capturing its own crash dump.

[1]: https://www.qemu.org/docs/master/specs/pvpanic.html
[2]: https://github.com/torvalds/linux/tree/master/drivers/misc/pvpanic
