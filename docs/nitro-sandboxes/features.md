# Nitro Sandbox features

This document describes the sandbox-specific features: the `/enclave` endpoint,
per-device DMB sizing, device hotplug, CPU allocation and accounting, NUMA
placement, attestation, the serial console and the jailer. For which standard
Firecracker features apply to a sandbox, see
[Comparison with KVM microVMs](comparison-with-kvm.md).

## `PUT /enclave`

`PUT /enclave` is what makes a Firecracker VM a sandbox: once it is set, even to
`{}`, `InstanceStart` launches through `/dev/nitro_enclaves` instead of KVM. It
must be sent before `InstanceStart`, which is when the sandbox and its slot are
created. Everything else, the machine config, boot source, drives, network
interfaces and vsock, uses the standard Firecracker API.

```json
{
    "debug_mode": true,
    "direct_mode": false,
    "cpu_overcommit": true
}
```

| Field            | Type | Default | Description                                                                                                                                            |
| ---------------- | ---- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `debug_mode`     | bool | `false` | Enable the debug serial console. In confidential mode this also locks the attestation PCRs to zero; for more, see [Attestation](#attestation).         |
| `direct_mode`    | bool | `false` | Run in direct (non-confidential) mode. The default is confidential mode.                                                                               |
| `cpu_overcommit` | bool | `false` | Let the Nitro System time-share the vCPUs over the parent's CPUs instead of claiming dedicated cores. For more, see [CPU allocation](#cpu-allocation). |
| `cpu_accounting` | bool | `false` | Attribute each vCPU's guest time to an `fc_vcpu` thread of the Firecracker process. For more, see [CPU accounting](#cpu-accounting).                   |
| `hotplug_mode`   | bool | `false` | Allow block and network devices to be attached after boot. For more, see [Device hotplug](#device-hotplug).                                            |
| `cpu_ids`        | list | `null`  | Explicit parent CPU IDs, one per vCPU. Auto-selected when omitted.                                                                                     |
| `numa_nodes`     | list | `null`  | Per-parent-NUMA-node placement of vCPUs and memory. Defaults to node 0. For more, see [NUMA placement](#numa-placement).                               |

Unknown fields are rejected.

`GET /enclave` returns the enclave configuration in effect, including the
normalized `numa_nodes` placement once the sandbox has started. It is also
reported under the `enclave` key of `GET /vm/config`.

## Devices

Devices are configured through the standard Firecracker endpoints and attached
to the sandbox when it starts:

- **Block**, `PUT /drives/{id}`, attached as virtio-blk. For how to configure
  it, see [Virtio-block device](../block.md).
- **Network**, `PUT /network-interfaces/{id}`, attached as virtio-net and backed
  by a TAP device on the parent. For the TAP setup, see
  [Network setup](../network-setup.md).
- **Vsock**, `PUT /vsock`, attached as virtio-vsock. For how to configure it,
  see [vsock](../vsock.md).
- **Entropy**, `PUT /entropy`, attached as virtio-rng. Direct mode only: the
  Nitro System rejects virtio-rng in a confidential sandbox. For how to
  configure it, see [Entropy device](../entropy.md).

Block devices appear in the guest in configuration order, `/dev/vda`, `/dev/vdb`
and so on, matching KVM microVMs. A sandbox can hold at most 32 devices in
total, including those hotplugged after boot.

### DMB size

In confidential mode the parent cannot reach guest RAM, so each block, network
and vsock device keeps its virtqueues in its own Device Memory Buffer (DMB), a
per-device memory region shared between the guest and the device backend in the
parent. For more about why, see
[Confidential mode](how-it-works.md#confidential-mode-default). The DMB is sized
by an optional `dmb_size_mib` field on that device's own request:
`PUT /drives/{id}`, `PUT /network-interfaces/{id}` or `PUT /vsock`. The size is
a multiple of 2 between 2 and 256 MiB, and defaults to 16 MiB when omitted. An
out-of-range value fails the device request itself. Devices can be sized
independently, for example to give a lightly used network interface a smaller
buffer than the default:

```bash
curl -X PUT http://localhost/network-interfaces/eth0 \
  --unix-socket /tmp/fc.sock \
  -d '{
    "iface_id": "eth0",
    "guest_mac": "06:00:AC:10:00:02",
    "host_dev_name": "tap0",
    "dmb_size_mib": 4
  }'
```

`GET /vm/config` reports each device's `dmb_size_mib`: the value sent before the
sandbox starts, and the size actually allocated once the device is attached,
including the 16 MiB default for a device that set none.

The field only has meaning where a DMB exists. Setting it on a device of a
direct-mode sandbox fails when the device is attached, at `InstanceStart` or on
a hotplug request. It is likewise rejected on a KVM microVM.

The guest kernel logs each DMB when the driver binds, which confirms that the
device is using one:

```console
virtio_blk virtio1: Enabled 16777216-byte Virtio DMB (lockless bitmap, 4096 slots) for 0000:04:00.0
```

## Device hotplug

With `hotplug_mode: true`, block and network devices can be added to a running
sandbox with the same `PUT /drives/{id}` and `PUT /network-interfaces/{id}`
requests used before boot. For the KVM microVM equivalent, see
[Device Hotplugging](../device-hotplug.md).

```bash
dd if=/dev/zero of=/tmp/scratch.ext4 bs=1M count=64
mkfs.ext4 /tmp/scratch.ext4

curl -X PUT http://localhost/drives/scratch \
  --unix-socket /tmp/fc.sock \
  -d '{
    "drive_id": "scratch",
    "path_on_host": "/tmp/scratch.ext4",
    "is_root_device": false,
    "is_read_only": false
  }'
```

The guest detects the device through native PCIe hotplug, so no manual PCI
rescan is needed. The guest kernel needs `CONFIG_HOTPLUG_PCI_PCIE=y`.

Limitations:

- Rejected unless the sandbox was started with `hotplug_mode: true`.
- `pcie_hotplug_ports`, which reserves hot-plug ports on a KVM microVM, is
  rejected at `InstanceStart`; `hotplug_mode` takes its place.
- Block and network devices only.
- Devices cannot be hot-unplugged.
- Virtio device reset is not yet supported: Firecracker does not reset the
  device, which is left in an undefined state that can misbehave or crash
  Firecracker. For more, see
  [Comparison with KVM microVMs](comparison-with-kvm.md#feature-support).
- A root device cannot be hotplugged.
- The 32-device limit includes hotplugged devices. Exceeding it fails the
  request with an error.
- In confidential mode a hotplugged device gets a DMB sized by its own
  `dmb_size_mib`, or 16 MiB when it sets none.

## CPU allocation

### Dedicated cores or overcommit

By default each vCPU is a dedicated CPU thread from the Nitro Enclaves CPU pool.
Cores are taken whole, both SMT siblings together, and are unavailable to the
parent's scheduler for as long as the sandbox runs. With the default dynamic
pool the CPUs stay online in the parent but are removed from its scheduler while
the sandbox holds them; a static `ne_cpus=` pool takes its CPUs offline when the
pool is set up. The guest sees the same layout: on an SMT x86_64 parent a 2-vCPU
sandbox reports one core with two threads, and on aarch64 each vCPU is its own
core.

Because cores are allocated whole, `vcpu_count` must be even in this mode on a
parent with SMT.

With `cpu_overcommit: true`, vCPUs do not claim cores. The Nitro System
time-shares them over the parent's CPUs, so no core leaves the parent. Any
`vcpu_count` is allowed, including odd counts and counts larger than the CPU
pool, up to the parent's vCPU count. An instance can then run more sandboxes
than it has spare cores, at the cost of those sandboxes sharing CPU time with
each other and with the parent. For the limits, see
[Sandbox limits](comparison-with-kvm.md#sandbox-limits).

### Explicit CPU selection

`cpu_ids` names the parent CPUs to use, one per vCPU. With dedicated cores the
vCPUs run on exactly those CPUs. With `cpu_overcommit` they still float over the
parent's CPUs, and the IDs only decide which NUMA node each vCPU belongs to:

```json
{
    "debug_mode": true,
    "cpu_ids": [2, 18]
}
```

With dedicated cores the IDs must form whole cores, so both SMT siblings of each
core must be listed. The parent reports them:

```bash
cat /sys/devices/system/cpu/cpu2/topology/thread_siblings_list
```

CPU 0 cannot be listed: the driver reads an ID of 0 as a request to pick any CPU
and substitutes one silently. When `cpu_ids` is omitted the driver picks all the
CPUs itself.

## CPU accounting

> [!WARNING]
>
> `cpu_accounting` is in
> [Developer Preview](../RELEASE_POLICY.md#developer-preview-features). It may
> have limitations, and its API or behavior may change in future releases.

Sandbox vCPUs are not threads of the Firecracker process, so by default their
CPU time does not appear in the parent's process accounting at all. With
`cpu_accounting: true`, Firecracker spawns one resident thread per vCPU, named
`fc_vcpu <N>`, and the driver attributes each vCPU's execution time to its
thread as *guest* time:

```console
$ ps -T -p $(pgrep -x firecracker) -o tid,comm
    TID COMMAND
3297130 firecracker
3297131 fc_api
3297165 fc_vcpu 0
3297166 fc_vcpu 1
```

The attributed time is `guest_time`, field 43 of `/proc/<pid>/task/<tid>/stat`.
Each thread's `guest_time` tracks the time its vCPU spent running, and the
process total is the sum across vCPUs.

`cpu_accounting` is independent of `cpu_overcommit` and the two compose in any
combination.

> [!NOTE]
>
> A cgroup on the parent neither accounts for nor constrains sandbox CPU time,
> because sandbox vCPUs are scheduled by the Nitro System rather than by the
> parent kernel. A `cpu.max` limit on the Firecracker process does not throttle
> the guest, and the cgroup's `cpu.stat` does not record the guest's work.
> `cpu_accounting` attributes the time instead. What bounds a sandbox's CPU
> consumption is the CPU pool with dedicated cores, and its `vcpu_count` with
> `cpu_overcommit`.

## NUMA placement

On a parent with several NUMA nodes, `numa_nodes` places slices of a sandbox's
vCPUs and memory on chosen parent nodes, keeping each node's vCPUs next to its
memory. Each entry describes one node:

```json
{
    "debug_mode": true,
    "numa_nodes": [
        {"parent_numa": 0, "vcpu_count": 2, "mem_size_mib": 256},
        {"parent_numa": 1, "vcpu_count": 2, "mem_size_mib": 256}
    ]
}
```

| Field          | Type | Description                                   |
| -------------- | ---- | --------------------------------------------- |
| `parent_numa`  | int  | Parent NUMA node to place this slice on.      |
| `vcpu_count`   | int  | Number of vCPUs to place on `parent_numa`.    |
| `mem_size_mib` | int  | Sandbox RAM in MiB to place on `parent_numa`. |

Omitting `numa_nodes` places the whole sandbox on parent node 0.

Rules, all enforced at `InstanceStart`:

- The `vcpu_count` sum must equal `machine-config.vcpu_count`, and the
  `mem_size_mib` sum must equal `machine-config.mem_size_mib`.
- No duplicate `parent_numa`, and no entry with zero vCPUs or zero memory.
- Every node's `mem_size_mib` except the one with the highest `parent_numa` must
  be a multiple of 128 MiB, so that guest NUMA boundaries land on memory section
  boundaries.
- An empty list is rejected.

When a placement spans more than one node the guest is given a matching NUMA
topology derived from the parent's, so `numactl --hardware` inside the sandbox
reflects where it really runs. The list is normalized, sorted by `parent_numa`,
and echoed back by `GET /enclave`.

`numa_nodes` composes with `cpu_overcommit`, so floating vCPUs are kept on the
node that holds their memory.

It also composes with `cpu_ids`. Memory placement always follows `numa_nodes`,
while explicit `cpu_ids` take over vCPU placement; the per-node `vcpu_count`
values are still checked for their sum but no longer drive placement, so the CPU
IDs must be on the intended nodes.

## Attestation

A confidential sandbox contains a Nitro Secure Module (NSM). The Nitro System
records the EIF's boot measurements in Platform Configuration Registers, as for
Nitro Enclaves, and the workload can ask the NSM for a signed attestation
document to present to a remote verifier. The measurements are taken and signed
by the Nitro System, not the parent, so a verifier can check them without
trusting the parent. For background on Nitro attestation documents, PCRs and
verifying them, see
[Cryptographic attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
in the AWS Nitro Enclaves User Guide.

The PCRs cover the EIF: the kernel, initrd and command line. Drive contents,
network traffic and devices attached after boot come from the parent and are not
measured, so a workload that relies on attestation must verify what it loads
from them.

Firecracker does not report the measurements of an EIF it builds. To attest
against known values, the operator builds the EIF and supplies it pre-built; for
how to boot a pre-built EIF, see [Boot images](getting-started.md#boot-images).
An EIF built for Nitro Enclaves lacks the sandbox capability flags, so it fails
at `InstanceStart`.

The NSM appears in the guest as virtio device type 33 (`0x21`), PCI ID
`1af4:1061`:

```console
$ lspci -nn | grep 1af4:1061
00:02.0 Communication controller [0780]: Red Hat, Inc. Device [1af4:1061]
```

To use it from the guest, the guest kernel needs the NSM driver
(`CONFIG_NSM=y`), which exposes `/dev/nsm`. The device is present whether or not
the driver is, so an absent `/dev/nsm` means a guest kernel without the driver,
not a missing device.

Caveats:

- `debug_mode: true` locks the PCRs to zero. The debug console becomes available
  and the sandbox runs normally, but its attestation documents no longer
  identify the image.
- Direct mode has no NSM device and no attestation, because the parent retains
  access to sandbox memory and so there is no confidentiality to attest to.

## Serial console

In debug mode Firecracker writes the guest's serial output to its standard
output, or to a file or named pipe set with `PUT /serial` before boot:

```bash
curl -X PUT http://localhost/serial \
  --unix-socket /tmp/fc.sock \
  -d '{"serial_out_path": "/tmp/fc-serial.out"}'
```

An optional `rate_limiter` token bucket bounds the output bandwidth. Without
`debug_mode` a sandbox produces no serial output.

The console is output only. There is no way to type into the guest through it;
an interactive session needs a network interface or a vsock connection.

## Jailer

Sandboxes run under the [jailer](../jailer.md) like any other microVM, with no
extra flag. When the parent has the Nitro Enclaves driver loaded, the jailer
creates `/dev/nitro_enclaves` inside the chroot and gives it to the jailed user,
as it does for the other device nodes Firecracker needs. Kernel images, rootfs
files and drive backing files go inside the chroot as usual.
