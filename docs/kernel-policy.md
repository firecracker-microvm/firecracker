# Firecracker's Kernel Support Policy

Being a virtual machine monitor, Firecracker represents a component in a
larger stack, one in which it is tightly coupled with the guest and host
kernels on which it is run. The presented kernel support policy aims at
offering customers predictability into future kernel related changes.

As of right now, Firecracker code from main branch is being validated
continuously on *4.14* and *5.10* host and guest kernels. While other
versions and other kernel configs might work, they are not periodically
validated in our test suite, and using them might result in unexpected behaviour.
Once enabled, a kernel version is supported for a **minimum of 2 years**.

We are validating the currently supported Firecracker releases as per
[Firecracker’s release policy](../docs/RELEASE_POLICY.md).
Starting with release `v1.0` each major and minor release will specify
the supported kernel versions. Adding support for a new kernel version
will result in a Firecracker release only if compatibility changes are
required.

The currently supported kernel versions can be seen in the table below.
Based on our user requests, every year we are considering for enablement
the latest LTS version.

<table>
  <tr>
    <th></th>
    <th>2022</th>
  </tr>
  <tr>
    <td>4.14</td>
    <td style="background-color:mediumseagreen">full support</td>
  </tr>
  <tr>
    <td>5.10</td>
    <td style="background-color:mediumseagreen">full support</td>
  </tr>
</table>

The guest kernel configs used in our validation pipelines
can be found [here](../resources/guest_configs/) while a breakdown
of the relevant guest kernel modules can be found in the next section.

## Guest kernel modules

Below is a per-functionality breakdown of guest kernel modules
relevant to Firecracker for all platforms:

* serial console - `CONFIG_SERIAL_8250_CONSOLE`, `CONFIG_PRINTK`
* initrd support - `CONFIG_BLK_DEV_INITRD`
* virtio devices - `CONFIG_VIRTIO_MMIO`
  * balloon - `CONFIG_MEMORY_BALLOON`, `CONFIG_VIRTIO_BALLOON`
  * block - `CONFIG_VIRTIO_BLK`
    * partuuid support - `CONFIG_MSDOS_PARTITION`
  * network - `CONFIG_VIRTIO_NET`
  * vsock - `CONFIG_VIRTIO_VSOCKETS`

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
the minimally required guest kernel modules for a successful microVM boot are:

* Booting with initrd:
  * `CONFIG_BLK_DEV_INITRD`
    * For aarch64, you also need `CONFIG_VIRTIO_MMIO` (for the serial device).
    * For x86_64, you also need `CONFIG_KVM_GUEST`.

* Booting with root block device:
  * `CONFIG_VIRTIO_BLK`
  * For x86_64, you also need `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` and `CONFIG_KVM_GUEST`.

If you wish to enable boot logs, make sure to also add
`CONFIG_SERIAL_8250_CONSOLE` and `CONFIG_PRINTK` to the guest kernel config.

## [Experimental] Snapshot compatibility across kernel versions

We have a mechanism in place to experiment with snapshot compatibility across
supported host kernel versions by generating snapshot artifacts through
[this tool](../tools/create_snapshot_artifact) and checking devices' functionality
using [this test](../tests/integration_tests/functional/test_snapshot_restore_cross_kernel.py).
The microVM snapshotted is built from [this configuration file](../tools/create_snapshot_artifact/complex_vm_config.json).
The test restores the snapshot and ensures that all the devices set-up
in the configuration file (network devices, disk, vsock, balloon and MMDS)
are operational post-load.

The tables below reflect the snapshot compatibility observed on Intel and AMD.
On ARM, snapshot restore between kernel versions is not possible due to
registers incompatibility.

### Intel

<table>
  <tr>
    <th></th>
    <th>Snapshot taken on host 4.14</th>
    <th>Snapshot taken on host 5.10</th>
  </tr>
  <tr>
    <th>Load snapshot on host 4.14</th>
    <td style="background-color:mediumseagreen">successful</td>
    <td style="background-color:darkred">unsuccessful due to unresponsive net devices</td>
  </tr>
  <tr>
    <th>Load snapshot on host 5.10</th>
    <td style="background-color:mediumseagreen">successful</td>
    <td style="background-color:mediumseagreen">successful</td>
  </tr>
</table>

### AMD

<table>
  <tr>
    <th></th>
    <th>Snapshot taken on host 4.14</th>
    <th>Snapshot taken on host 5.10</th>
  </tr>
  <tr>
    <th>Load snapshot on host 4.14</th>
    <td style="background-color:mediumseagreen">successful</td>
    <td style="background-color:mediumseagreen">unsuccessful due to mismatch in MSRs</td>
  </tr>
  <tr>
    <th>Load snapshot on host 5.10</th>
    <td style="background-color:mediumseagreen">successful</td>
    <td style="background-color:mediumseagreen">successful</td>
  </tr>
</table>
