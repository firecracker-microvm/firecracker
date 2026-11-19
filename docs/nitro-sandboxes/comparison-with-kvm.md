# Nitro Sandboxes compared with KVM microVMs

This document describes the differences between running a guest as a KVM
microVM, where Firecracker drives `/dev/kvm` on the host, and as a Nitro
Sandbox, where it drives `/dev/nitro_enclaves` and the Nitro System runs the
guest. It also lists which features and limits apply to a sandbox.

## What differs from a KVM microVM

A sandbox is a different backend, not a different device model, so most of a KVM
microVM setup carries over: the same REST API, the same virtio devices, the same
jailer, the same TAP networking. The differences:

- **No KVM on the parent and no bare-metal instance.** Firecracker needs no
  `/dev/kvm` on the parent and no hardware virtualization exposed to it, so a
  sandbox runs on ordinary virtualized instance types. A KVM microVM needs a
  `.metal` instance on EC2, or else nested virtualization; a sandbox needs an
  [instance type that supports AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-reqs),
  with the feature enabled at launch.
- **Isolation is enforced by the Nitro System**, not by KVM and the parent
  kernel. In confidential mode the parent has no access to guest memory.
- **Guest CPUs are not parent threads.** They are first-level hardware CPUs
  scheduled by the Nitro System, so the parent's scheduler and cgroups do not
  govern them, and per-thread CPU accounting needs
  [`cpu_accounting`](features.md#cpu-accounting).
- **Memory is donated whole at boot** from a physically contiguous pool, not
  faulted in on demand, so memory overcommit is not yet supported and there is
  no huge-page backing.
- **Boot goes through UEFI from an EIF**, so the guest needs an EFI-bootable
  kernel image rather than the `vmlinux` used for microVMs.
- **PCIe only.** The legacy MMIO transport is not available.
- **No snapshots and no paused state**, so the snapshot and pause/resume APIs do
  not apply.

## Feature support

| Feature                                                                 | KVM microVM  | Sandbox (direct) | Sandbox (confidential) |
| ----------------------------------------------------------------------- | :----------: | :--------------: | :--------------------: |
| [Block devices (virtio-blk)](../block.md)                               |     yes      |       yes        |          yes           |
| Network devices (virtio-net)                                            |     yes      |       yes        |          yes           |
| [Vsock](../vsock.md)                                                    |     yes      |       yes        |          yes           |
| [Entropy device (virtio-rng)](../entropy.md)                            |     yes      |       yes        |        rejected        |
| [MMDS](../mmds/mmds-user-guide.md)                                      |     yes      |       yes        |          yes           |
| [Block device update (`PATCH /drives`)](../api_requests/patch-block.md) |     yes      |       yes        |          yes           |
| [Device hotplug (block, net)](../device-hotplug.md)                     |    opt-in    |      opt-in      |         opt-in         |
| Device hot-unplug                                                       |     yes      |     rejected     |        rejected        |
| Virtio device reset (block, net)                                        |     yes      |        no        |           no           |
| [Initrd](../initrd.md)                                                  |     yes      |       yes        |          yes           |
| [Jailer](../jailer.md)                                                  |     yes      |       yes        |          yes           |
| [Pmem devices](../pmem.md)                                              |     yes      |     rejected     |        rejected        |
| [Memory hotplug (virtio-mem)](../memory-hotplug.md)                     |     yes      |     rejected     |        rejected        |
| [Balloon device](../ballooning.md)                                      |     yes      |     rejected     |        rejected        |
| [vhost-user block](../api_requests/block-vhost-user.md)                 |     yes      |     rejected     |        rejected        |
| [Huge pages](../hugepages.md)                                           |     yes      |     rejected     |        rejected        |
| [CPU templates](../cpu_templates/cpu-templates.md)                      |     yes      |     rejected     |        rejected        |
| Guest SMT configuration (`smt`)                                         |     yes      |     rejected     |        rejected        |
| Dirty page tracking                                                     |     yes      |     rejected     |        rejected        |
| [Snapshot and restore](../snapshotting/snapshot-support.md)             |     yes      |     rejected     |        rejected        |
| Pause and resume                                                        |     yes      |     rejected     |        rejected        |
| Graceful external shutdown (`SendCtrlAltDel`)                           | yes (x86_64) |     rejected     |        rejected        |
| MMIO transport                                                          |     yes      |        no        |           no           |
| Attestation (NSM, PCRs)                                                 |      no      |        no        |          yes           |
| [CPU overcommit](features.md#cpu-allocation)                            |     yes      |       yes        |          yes           |
| [CPU accounting](features.md#cpu-accounting)                            |     yes      |       yes        |          yes           |
| [NUMA placement](features.md#numa-placement)                            |      no      |       yes        |          yes           |

How to read **rejected** and **no**:

- **rejected** means the request fails with an error rather than being accepted
  and quietly ignored. Configuration is refused at `InstanceStart`: unsupported
  machine-config fields and devices name the feature in the error; for the error
  text, see
  [`A Nitro Enclave does not support ...`](getting-started.md#a-nitro-enclave-does-not-support--at-start).
  The entropy device is refused by the Nitro System. Runtime operations, such as
  hot-unplug, pause and resume, fail when called, and loading a snapshot fails
  once `PUT /enclave` has been sent.
- **no** means the capability is not available for that kind of VM: sandboxes
  are PCIe-only, only a confidential sandbox has an attestation device, and
  Firecracker has no NUMA placement option for a KVM microVM.

Notes on the table:

- A KVM microVM's vCPUs are host threads, so it gets CPU overcommit and CPU
  accounting without any option, and its NUMA placement is done from the host.

- Device hotplug is opt-in on both: a KVM microVM reserves PCIe root ports with
  the `pcie_hotplug_ports` machine-config field, and a sandbox is started with
  `hotplug_mode`. A sandbox rejects `pcie_hotplug_ports` at `InstanceStart`.

- Virtio device reset is not yet supported in a sandbox. When the guest resets a
  virtio device, for example by rebinding its driver, recovering from a device
  error or kexec'ing into a new kernel, the device is neither reset nor
  deactivated, and its backend keeps serving the queues set up before the reset.
  The device is left in an undefined state in which it can misbehave or cause
  Firecracker to crash.

- The entropy device is refused in confidential mode because the parent is
  untrusted there, and the guest kernel would credit a parent-supplied random
  source as entropy.

- The per-device `dmb_size_mib` field exists for sandboxes only. A KVM microVM
  rejects it.

- Huge pages and dirty page tracking do not apply because donated memory is not
  ordinary anonymous memory. It appears in the parent as a shared mapping of
  `/dev/nitro_enclaves` served from the driver's contiguous pool, which neither
  transparent huge pages nor hugetlbfs can back.

- No jailer flag is needed for a sandbox; for what the jailer sets up, see
  [Jailer](features.md#jailer).

## Direct mode and confidential mode

| Capability                            | Direct            | Confidential                          |
| ------------------------------------- | ----------------- | ------------------------------------- |
| Parent access to sandbox memory       | read/write        | none                                  |
| Attestation (NSM device, PCRs)        | not available     | available                             |
| Virtqueue placement                   | guest RAM         | Device Memory Buffers                 |
| Per-device `dmb_size_mib`             | rejected          | 2 to 256 MiB, default 16              |
| Guest kernel needs DMB virtio patches | no                | yes                                   |
| Entropy device                        | supported         | rejected                              |
| Debug console (`debug_mode`)          | supported         | supported, zeroes the PCRs            |
| Device hotplug                        | supported         | supported                             |
| NUMA placement                        | supported         | supported                             |
| CPU overcommit and accounting         | supported         | supported                             |
| Trust model                           | parent is trusted | workload is protected from the parent |

Confidential mode is the default. Direct mode gives up protection from the
parent, and attestation, for lower I/O overhead.

## Architectures

Both x86_64 (Intel and AMD) and aarch64 (AWS Graviton) parents are supported.
The guest kernel image format is the one difference; for what each needs, see
[Guest kernel](getting-started.md#guest-kernel).

## Sandbox limits

| Resource                      | Limit                                                            |
| ----------------------------- | ---------------------------------------------------------------- |
| vCPUs per sandbox             | up to the parent's vCPU count, and at most 1024                  |
| vCPU count granularity        | whole cores with dedicated CPUs, any count with `cpu_overcommit` |
| Memory size                   | at least 64 MiB, a multiple of 2 MiB                             |
| Per-NUMA-node memory slice    | a multiple of 128 MiB, except the highest `parent_numa`          |
| Devices per sandbox           | 32, including hotplugged devices                                 |
| Per-device DMB (confidential) | 2 to 256 MiB, a multiple of 2 MiB                                |
| Sandbox vCPUs per instance    | in total, 5 times the parent's vCPU count                        |

### Sandboxes per instance

The vCPUs of all the sandboxes on a parent can add up to at most five times the
parent's vCPU count. A 4-vCPU instance can hold, for example, ten 2-vCPU
sandboxes with `cpu_overcommit`, and the sandboxes on a 96-vCPU instance can
total 480 vCPUs.

The
[Amazon EC2 User Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nitro-sandboxes.html#nitro-sandboxes-considerations)
is the reference for this limit.

This limit is an upper bound, not the only one. Because a sandbox holds its full
memory for its whole life, the memory pool also bounds how many can exist at
once, and with dedicated cores so does the CPU pool, since each sandbox takes
whole cores from it.

The slot budget also bounds how many sandboxes a parent can hold at once; for
how to raise it, see [Slot budget](getting-started.md#slot-budget).
