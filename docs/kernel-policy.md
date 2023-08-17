# Firecracker's Kernel Support Policy

Once officially supported kernel versions are supported for a **minimum of 2 years**.

We are validating the currently supported Firecracker releases as per
[Firecracker’s release policy](../docs/RELEASE_POLICY.md). Starting with release
`v1.0` each major and minor release will specify the supported kernel versions.
Adding support for a new kernel version will result in a Firecracker release
only if compatibility changes are required.

The guest kernel configs used in our validation pipelines
can be found [here](../resources/guest_configs/) while a breakdown
of the relevant guest kernel modules can be found in the next section.

## Guest kernel configuration items

Some configuration items that may be of interest are:

* serial console - `CONFIG_SERIAL_8250_CONSOLE`, `CONFIG_PRINTK`
* initrd support - `CONFIG_BLK_DEV_INITRD`
* virtio devices - `CONFIG_VIRTIO_MMIO`
  * balloon - `CONFIG_MEMORY_BALLOON`, `CONFIG_VIRTIO_BALLOON`
  * block - `CONFIG_VIRTIO_BLK`
    * partuuid support - `CONFIG_MSDOS_PARTITION`
  * network - `CONFIG_VIRTIO_NET`
  * vsock - `CONFIG_VIRTIO_VSOCKETS`
  * entropy - `CONFIG_HW_RANDOM_VIRTIO`
* guest RNG - `CONFIG_RANDOM_TRUST_CPU`
  * use CPU RNG instructions (if present) to initialize RNG. Available for >= 5.10

There are also guest config options which are dependant on the platform
on which Firecracker is run:

### ARM

* timekeeping - `CONFIG_ARM_AMBA`, `CONFIG_RTC_DRV_PL031`
* serial console - `CONFIG_SERIAL_OF_PLATFORM`

### x86_64

* timekeeping - `CONFIG_KVM_GUEST` (which enables CONFIG_KVM_CLOCK)
* high precision timekeeping - `CONFIG_PTP_1588_CLOCK`, `CONFIG_PTP_1588_CLOCK_KVM`
* external clean shutdown - `CONFIG_SERIO_I8042`, `CONFIG_KEYBOARD_ATKBD`
* virtio devices - `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES`

#### Minimal boot requirements

Depending on the source of boot (either from a block device or from an initrd),
the minimal configuration for a guest kernel for a successful microVM boot is:

* Booting with initrd:
  * `CONFIG_BLK_DEV_INITRD=y`
    * aarch64 `CONFIG_VIRTIO_MMIO=y` (for the serial device).
    * x86_64 `CONFIG_KVM_GUEST=y`.

* Booting with root block device:
  * aarch64
    * `CONFIG_VIRTIO_BLK=y`
  * x86_64
    * `CONFIG_VIRTIO_BLK=y`
    * `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`
    * `CONFIG_KVM_GUEST=y`.

*Optional*: To enable boot logs set `CONFIG_SERIAL_8250_CONSOLE=y` and
`CONFIG_PRINTK=y` in the guest kernel config.

## Caveats

* When using a 4.14 host and a 5.10 guest, we disable the SVE extension in the
  guest. This is due to the introduction of the SVE extension in Graviton3,
  which causes the default 5.10 guest (with SVE support enabled), to crash if
  run with a 4.14 host which does not support SVE.
* [Snapshot compatibility across kernel versions](snapshotting/snapshot-support.md#snapshot-compatibility-across-kernel-versions)
