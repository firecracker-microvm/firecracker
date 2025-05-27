# Firecracker's Kernel Support Policy

Firecracker is tightly coupled with the guest and host kernels on which it is
run. This document presents our kernel support policy which aims to help our
customers choose host and guest OS configuration, and predict future kernel
related changes.

We are continuously validating the currently supported Firecracker releases (as
per [Firecracker’s release policy](../docs/RELEASE_POLICY.md)) using a
combination of all supported host and guest kernel versions in the table below.

Once a kernel version is officially added, it is supported for a **minimum of 2
years**. At least 2 major guest and host versions will be supported at any time.
When support is added for a third kernel version, the oldest will be deprecated
and removed in a following release, after its minimum end of support date.

**Note** While other versions and other kernel configs might work, they are not
periodically validated in our test suite, and using them might result in
unexpected behaviour. Starting with release `v1.0` each major and minor release
will specify the supported kernel versions.

### Host Kernel

| Page size | Host kernel | Min. version | Min. end of support |
| --------: | ----------: | -----------: | ------------------: |
|        4K |       v5.10 |       v1.0.0 |          2024-01-31 |
|        4K |        v6.1 |       v1.5.0 |          2025-10-12 |

### Guest Kernel

| Page size | Guest kernel | Min. version | Min. end of support |
| --------: | -----------: | -----------: | ------------------: |
|        4K |        v5.10 |       v1.0.0 |          2024-01-31 |
|        4K |         v6.1 |       v1.9.0 |          2026-09-02 |

The guest kernel configs used in our validation pipelines can be found
[here](../resources/guest_configs/) while a breakdown of the relevant guest
kernel modules can be found in the next section.

We use these configurations to build microVM-specific kernels vended by Amazon
Linux. microVM kernel source code is published in the Amazon Linux
[linux repo](https://github.com/amazonlinux/linux) under tags in the form of
`microvm-kernel-*`, e.g. 6.1.128-3.201.amazn2023 kernel can be found
[here](https://github.com/amazonlinux/linux/tree/microvm-kernel-6.1.128-3.201.amzn2023).
These kernels may have diverged from the equivalent mainline versions, as we
often backport patches that we require for supporting Firecracker features not
present in the kernel versions we officially support. As a result, kernel
configurations found in this repo should be used to build exclusively the
aforementioned Amazon Linux kernels. We do not guarantee that using these
configurations to build upstream kernels, will work or produce usable kernel
images.

## Guest kernel configuration items

The configuration items that may be relevant for Firecracker are:

- serial console - `CONFIG_SERIAL_8250_CONSOLE`, `CONFIG_PRINTK`
- initrd support - `CONFIG_BLK_DEV_INITRD`
- virtio devices - `CONFIG_VIRTIO_MMIO`
  - balloon - `CONFIG_MEMORY_BALLOON`, `CONFIG_VIRTIO_BALLOON`
  - block - `CONFIG_VIRTIO_BLK`
    - partuuid support - `CONFIG_MSDOS_PARTITION`
  - network - `CONFIG_VIRTIO_NET`
  - vsock - `CONFIG_VIRTIO_VSOCKETS`
  - entropy - `CONFIG_HW_RANDOM_VIRTIO`
- guest RNG - `CONFIG_RANDOM_TRUST_CPU`
  - use CPU RNG instructions (if present) to initialize RNG. Available for >=
    5.10
- ACPI support - `CONFIG_ACPI` and `CONFIG_PCI`

There are also guest config options which are dependant on the platform on which
Firecracker is run:

### ARM

- timekeeping - `CONFIG_ARM_AMBA`, `CONFIG_RTC_DRV_PL031`
- serial console - `CONFIG_SERIAL_OF_PLATFORM`

### x86_64

- timekeeping - `CONFIG_KVM_GUEST` (which enables CONFIG_KVM_CLOCK)
- high precision timekeeping - `CONFIG_PTP_1588_CLOCK`,
  `CONFIG_PTP_1588_CLOCK_KVM`
- external clean shutdown - `CONFIG_SERIO_I8042`, `CONFIG_KEYBOARD_ATKBD`
- virtio devices - `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES`

#### Minimal boot requirements

Depending on the source of boot (either from a block device or from an initrd),
the minimal configuration for a guest kernel for a successful microVM boot is:

- Booting with initrd:

  - `CONFIG_BLK_DEV_INITRD=y`
    - aarch64 `CONFIG_VIRTIO_MMIO=y` (for the serial device).
    - x86_64 `CONFIG_KVM_GUEST=y`.

- Booting with root block device:

  - aarch64
    - `CONFIG_VIRTIO_BLK=y`
  - x86_64
    - `CONFIG_VIRTIO_BLK=y`
    - `CONFIG_ACPI=y`
    - `CONFIG_PCI=y`
    - `CONFIG_KVM_GUEST=y`.

*Optional*: To enable boot logs set `CONFIG_SERIAL_8250_CONSOLE=y` and
`CONFIG_PRINTK=y` in the guest kernel config.

##### Booting with ACPI (x86_64 only):

Firecracker supports booting kernels with ACPI support. The relevant
configurations for the guest kernel are:

- `CONFIG_ACPI=y`
- `CONFIG_PCI=y`

Please note that Firecracker does not support PCI devices. The `CONFIG_PCI`
option is needed for ACPI initialization inside the guest.

ACPI supersedes the legacy way of booting a microVM, i.e. via MPTable and
command line parameters for VirtIO devices.

We suggest that users disable MPTable and passing VirtIO devices via kernel
command line parameters. These boot mechanisms are now deprecated. Users can
disable these features by disabling the corresponding guest kernel configuration
parameters:

- `CONFIG_X86_MPPARSE=n`
- `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=n`

During the deprecation period Firecracker will continue to support the legacy
way of booting a microVM. Firecracker will be able to boot kernels with the
following configurations:

- Only ACPI
- Only legacy mechanisms
- Both ACPI and legacy mechanisms

## Caveats

- [Snapshot compatibility across kernel versions](snapshotting/snapshot-support.md#snapshot-compatibility-across-kernel-versions)
- When booting with kernels that support both ACPI and legacy boot mechanisms
  Firecracker passes VirtIO devices to the guest twice, once through ACPI and a
  second time via kernel command line parameters. In these cases, the guest
  tries to initialize devices twice. The second time, initialization fails and
  the guest will emit warning messages in `dmesg`, however the devices will work
  correctly.
