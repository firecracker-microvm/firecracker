# How Nitro Sandboxes work

This document gives a high-level overview of how Nitro Sandboxes work and the
role Firecracker plays in them. For the terms used here, see the
[glossary](README.md#glossary).

## Firecracker's role

Firecracker is the sandbox's *frontend*. It owns the API socket, the device
backends and the sandbox's lifecycle, and it drives the launch through ioctls on
`/dev/nitro_enclaves`:

1. Check which capabilities the driver advertises, then create the sandbox.
1. Add vCPUs, either dedicated cores or floating vCPUs under `cpu_overcommit`,
   optionally on explicit CPU IDs; for more about the options, see
   [CPU allocation](features.md#cpu-allocation).
1. Allocate one or more regions of physically contiguous memory, write the EIF
   (the sandbox's boot image) into them, and donate them to the sandbox.
1. Register each configured virtio device with the driver.
1. Start the sandbox. The Nitro System boots the EIF; for more about how, see
   [Booting](#booting).
1. Once the guest's virtio drivers signal that they are ready, Firecracker's
   device backends serve I/O through shared virtqueues. The Nitro System relays
   notifications between the guest and Firecracker in both directions.

Firecracker is not in the guest's CPU path and vCPUs are not threads of
Firecracker. Sandbox vCPUs are first-level, hardware-virtualized CPUs scheduled
by the Nitro System.

## The isolation boundary

The Nitro System enforces the isolation boundary between the parent instance and
its sandboxes. For an overview of the isolation model, see the
[Amazon EC2 User Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nitro-sandboxes.html#nitro-sandboxes-how-it-works).
Two trust surfaces remain:

In confidential mode, the parent is untrusted from the sandbox's point of view.
The Nitro System is designed to keep the parent, including its kernel and
Firecracker, from reading or writing the sandbox's RAM. As the parent handles
the data coming from the guest through the virtio devices, the sandbox should
adopt protections (like encryption and verification) so the parent can neither
read nor tamper with it.

In both modes, the sandbox is untrusted from the parent's point of view.
Everything a sandbox writes into a shared virtqueue is attacker-controlled input
to the parent's device backends.

## Memory modes

A sandbox runs in one of two modes, chosen with the `direct_mode` field of the
enclave configuration and fixed for the sandbox's lifetime.

### Confidential mode (default)

The Nitro System takes the donated memory out of the parent's reach. The parent
instance, including Firecracker itself, cannot read or write the sandbox's RAM
while it runs. An NSM device is present in the guest, so the workload can prove
what it is running before it is trusted with secrets. For more about
attestation, see [Attestation](features.md#attestation).

Because the parent cannot reach guest RAM, virtqueues cannot live there. Each
device instead gets a Device Memory Buffer (DMB), a per-device memory region
shared between the guest and the device backend in the parent, sized by that
device's `dmb_size_mib` and 16 MiB by default. The guest's virtio driver routes
that device's DMA through the DMB and nothing else in guest memory is exposed.
This is why confidential mode needs a guest kernel with the DMB virtio patches.

### Direct mode

The parent keeps read/write access to the sandbox's memory. There is no NSM
device and no attestation. Virtqueues live in ordinary guest RAM, so no DMB is
allocated and an unpatched virtio driver works.

Direct mode is simpler and has lower I/O overhead. The parent and other
sandboxes are still isolated from the guest, but the guest is not protected from
the parent.

## Memory donation

Sandbox memory is allocated and donated in full when the sandbox starts. It is
not faulted in on demand, and memory overcommit is not yet supported. In both
modes the memory is committed to the sandbox and unavailable to the parent's
allocator for as long as the sandbox lives; in direct mode the parent
additionally keeps read/write access to it. The memory returns to the parent
when the sandbox exits.

The memory comes from the Nitro Enclaves driver's pool of physically contiguous
memory, accounted per NUMA node, and is donated in 2 MiB-aligned regions. On a
parent with several NUMA nodes, slices of a sandbox's memory and vCPUs can be
placed on chosen nodes; for more about placement, see
[NUMA placement](features.md#numa-placement).

Two things follow from donated memory not being ordinary anonymous memory.
Huge-page backing does not apply, so the `huge_pages` machine-config field is
rejected. And the Nitro Enclaves driver zeroes the memory before donating it, so
a sandbox does not see data the parent left there.

## Booting

A sandbox boots from an EIF, the measured Enclave Image Format artifact that
packages the guest kernel, an optional initrd, the kernel command line, and the
capabilities the image was built for. Firecracker can either construct an EIF in
memory on boot from supplied artifacts, or directly boot an operator-supplied
EIF; for more about the two paths, see
[Boot images](getting-started.md#boot-images).

The capability flags in the EIF header must match what the frontend requests at
launch. That match is what keeps attestation meaningful: an image built for one
configuration cannot be started under another.

Boot itself runs through UEFI firmware, which loads the kernel from the EIF. The
Nitro System supplies ACPI tables and the PCIe topology, so a standard
distribution kernel enumerates its devices the ordinary way. The guest kernel
must therefore be EFI-bootable, which on x86_64 means an EFI-stub `bzImage`
rather than the `vmlinux` used for KVM microVMs.

## Lifecycle

A sandbox goes straight to `Running` when `InstanceStart` completes. There is no
paused state, so the pause, resume and snapshot APIs are rejected; for the full
list, see [Feature support](comparison-with-kvm.md#feature-support).

When the guest shuts down or reboots, for example with `poweroff` or `reboot`,
the sandbox is torn down, its vCPUs and memory return to the parent's pools, and
the Firecracker process exits, the same contract as a KVM microVM. The sandbox
is also torn down when its `/dev/nitro_enclaves` file descriptor is closed, so
killing the Firecracker process terminates it too.

A sandbox is stopped from the parent by shutting the guest down from inside or
by killing the Firecracker process. `SendCtrlAltDel` is not supported, so there
is no graceful external shutdown.

Each sandbox occupies a slot, a Nitro System resource held from creation until
teardown. The slot budget caps how many sandboxes one instance can hold at once;
for more about raising it, see [Slot budget](getting-started.md#slot-budget).
