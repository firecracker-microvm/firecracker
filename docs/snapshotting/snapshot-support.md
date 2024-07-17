# Firecracker Snapshotting

## Table of Contents

- [What is microVM snapshotting?](#about-microvm-snapshotting)
- [Snapshotting in Firecracker](#snapshotting-in-firecracker)
  - [Supported platforms](#supported-platforms)
  - [Overview](#overview)
  - [Snapshot files management](#snapshot-files-management)
  - [Performance](#performance)
  - [Developer preview status](#developer-preview-status)
  - [Limitations](#limitations)
- [Firecracker Snapshotting characteristics](#firecracker-snapshotting-characteristics)
- [Snapshot versioning](#snapshot-versioning)
- [Snapshot API](#snapshot-api)
  - [Pausing the microVM](#pausing-the-microvm)
  - [Creating snapshots](#creating-snapshots)
    - [Creating full snapshots](#creating-full-snapshots)
    - [Creating diff snapshots](#creating-diff-snapshots)
  - [Resuming the microVM](#resuming-the-microvm)
  - [Loading snapshots](#loading-snapshots)
- [Provisioning host disk space for snapshots](#provisioning-host-disk-space-for-snapshots)
- [Ensure continued network connectivity for clones](#ensure-continued-network-connectivity-for-clones)
- [Snapshot security and uniqueness](#snapshot-security-and-uniqueness)
  - [Secure and insecure usage examples](#usage-examples)
  - [Reusing snapshotted states securely](#reusing-snapshotted-states-securely)
- [Vsock device limitation](#vsock-device-limitation)

## About microVM snapshotting

MicroVM snapshotting is a mechanism through which a running microVM and its
resources can be serialized and saved to an external medium in the form of a
`snapshot`. This snapshot can be later used to restore a microVM with its guest
workload at that particular point in time.

## Snapshotting in Firecracker

### Supported platforms

> \[!WARNING\]
>
> The Firecracker snapshot feature is in
> [developer preview](../RELEASE_POLICY.md) on all CPU micro-architectures
> listed in [README](../../README.md#supported-platforms). See
> [this section](#developer-preview-status) for more info.

### Overview

A Firecracker microVM snapshot can be used for loading it later in a different
Firecracker process, and the original guest workload is being simply resumed.

The original guest which the snapshot is created from, should see no side
effects from this process (other than the latency introduced by the snapshot
creation process).

Both network and vsock packet loss can be expected on guests that are resumed
from snapshots in another Firecracker process. It is also not guaranteed that
the state of the network connections survives the process.

In order to make restoring possible, Firecracker snapshots save the full state
of the following resources:

- the guest memory,
- the emulated HW state (both KVM and Firecracker emulated HW).

The state of the components listed above is generated independently, which
brings flexibility to our snapshotting support. This means that taking a
snapshot results in multiple files that are composing the full microVM snapshot:

- the guest memory file,
- the microVM state file,
- zero or more disk files (depending on how many the guest had; these are
  **managed by the users**).

The design allows sharing of memory pages and read only disks between multiple
microVMs. When loading a snapshot, instead of loading at resume time the full
contents from file to memory, Firecracker creates a
[MAP_PRIVATE mapping](http://man7.org/linux/man-pages/man2/mmap.2.html) of the
memory file, resulting in runtime on-demand loading of memory pages. Any
subsequent memory writes go to a copy-on-write anonymous memory mapping. This
has the advantage of very fast snapshot loading times, but comes with the cost
of having to keep the guest memory file around for the entire lifetime of the
resumed microVM.

### Snapshot files management

The Firecracker snapshot design offers a very simple interface to interact with
snapshots but provides no functionality to package or manage them on the host.

The [threat containment model](../design.md#threat-containment) states that the
host, host/API communication and snapshot files are trusted by Firecracker.

To ensure a secure integration with the snapshot functionality, users need to
secure snapshot files by implementing authentication and encryption schemes
while managing their lifecycle or moving them across the trust boundary, like
for example when provisioning them from a repository to a host over the network.

Firecracker is optimized for fast load/resume, and it's designed to do some very
basic sanity checks only on the vm state file. It only verifies integrity using
a 64-bit CRC value embedded in the vm state file, but this is only a partial
measure to protect against accidental corruption, as the disk files and memory
file need to be secured as well. It is important to note that CRC computation is
validated before trying to load the snapshot. Should it encounter failure, an
error will be shown to the user and the Firecracker process will be terminated.

### Performance

The Firecracker snapshot create/resume performance depends on the memory size,
vCPU count and emulated devices count. The Firecracker CI runs snapshot tests on
all [supported platforms](../../README.md#tested-platforms).

### Developer preview status

The snapshot functionality is still in developer preview due to the following:

- Poor entropy and replayable randomness when resuming multiple microvms from
  the same snapshot. We do not recommend to use snapshotting in production if
  there is no mechanism to guarantee proper secrecy and uniqueness between
  guests. Please see
  [Snapshot security and uniqueness](#snapshot-security-and-uniqueness).

### Limitations

- Currently on aarch64 platforms only lower 128 bits of any register are saved
  due to the limitations of `get/set_one_reg` from `kvm-ioctls` crate that
  Firecracker uses to interact with KVM. This creates an issue with newer
  aarch64 CPUs with support for registers with width greater than 128 bits,
  because these registers will be truncated before being stored in the snapshot.
  This can lead to uVM failure if restored from such snapshot. Because registers
  wider than 128 bits are usually used in SVE instructions, the best way to
  mitigate this issue is to ensure that the software run in uVM does not use SVE
  instructions during snapshot creation. An alternative way is to use
  [CPU templates](../cpu_templates/cpu-templates.md) to disable SVE related
  features in uVM.
- High snapshot latency on 5.4+ host kernels due to cgroups V1. We strongly
  recommend to deploy snapshots on cgroups V2 enabled hosts for the implied
  kernel versions -
  [related issue](https://github.com/firecracker-microvm/firecracker/issues/2129).
- Guest network connectivity is not guaranteed to be preserved after resume. For
  recommendations related to guest network connectivity for clones please see
  [Network connectivity for clones](network-for-clones.md).
- Vsock device does not have full snapshotting support. Please see
  [Vsock device limitation](#vsock-device-limitation).
- Snapshotting on arm64 works for both GICv2 and GICv3 enabled guests. However,
  restoring between different GIC version is not possible.
- If a [CPU template](../cpu_templates/cpu-templates.md) is not used on x86_64,
  overwrites of `MSR_IA32_TSX_CTRL` MSR value will not be preserved after
  restoring from a snapshot.
- Resuming from a snapshot that was taken during early stages of the guest
  kernel boot might lead to crashes upon snapshot resume. We suggest that users
  take snapshot after the guest microVM kernel has booted. Please see
  [VMGenID device limitation](#vmgenid-device-limitation).

## Firecracker Snapshotting characteristics

- Fresh Firecracker microVMs are booted using `anonymous` memory, while microVMs
  resumed from snapshot load memory on-demand from the snapshot and
  copy-on-write to anonymous memory.
- Resuming from a snapshot is optimized for speed, while taking a snapshot
  involves some extra CPU cycles for synchronously writing dirty memory pages to
  the memory snapshot file. Taking a snapshot of a fresh microVM, on which dirty
  pages tracking is not enabled, results in the full contents of guest memory
  being written to the snapshot.
- The _memory file_ and _microVM state file_ are generated by Firecracker on
  snapshot creation. The disk contents are _not_ explicitly flushed to their
  backing files.
- The API calls exposing the snapshotting functionality have clear
  **Prerequisites** that describe the requirements on when/how they should be
  used.
- The Firecracker microVM's MMDS config is included in the snapshot. However,
  the data store is not persisted across snapshots.
- Configuration information for metrics and logs are not saved to the snapshot.
  These need to be reconfigured on the restored microVM.
- On x86_64, if a vCPU has MSR_IA32_TSC_DEADLINE set to 0 when a snapshot is
  taken, Firecracker replaces it with the MSR_IA32_TSC value from the same vCPU.
  This is to guarantee that the vCPU will continue receiving TSC interrupts
  after restoring from the snapshot even if an interrupt is lost when taking a
  snapshot.

## Snapshot versioning

The microVM state snapshot file uses a data format that has a version in the
form of `MAJOR.MINOR.PATCH`. Each Firecracker binary supports a fixed version of
the snapshot data format. When creating a snapshot, Firecracker will use the
supported data format version. When loading snapshots, Firecracker will check
that the snapshot version is compatible with the version it supports. More
information about the snapshot data format and details about snapshot data
format versions can be found at [versioning](./versioning.md).

## Snapshot API

Firecracker exposes the following APIs for manipulating snapshots: `Pause`,
`Resume` and `CreateSnapshot` can be called only after booting the microVM,
while `LoadSnapshot` is allowed only before boot.

### Pausing the microVM

To create a snapshot, first you have to pause the running microVM and its vCPUs
with the following API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PATCH 'http://localhost/vm' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
            "state": "Paused"
    }'
```

**Prerequisites**: The microVM is booted. Successive calls of this request keep
the microVM in the `Paused` state. **Effects**:

- _on success_: microVM is guaranteed to be `Paused`.
- _on failure_: no side-effects.

### Creating snapshots

Now that the microVM is paused, you can create a snapshot, which can be either a
`full`one or a `diff` one. Full snapshots always create a complete, resume-able
snapshot of the current microVM state and memory. Diff snapshots save the
current microVM state and the memory dirtied since the last snapshot (full or
diff). Diff snapshots are not resume-able, but can be merged into a full
snapshot. In this context, we will refer to the base as the first memory file
created by a `/snapshot/create` API call and the layer as a memory file created
by a subsequent `/snapshot/create` API call. The order in which the snapshots
were created matters and they should be merged in the same order in which they
were created. To merge a `diff` snapshot memory file on top of a base, users
should copy its content over the base. This can be done using the `rebase-snap`
(deprecated) or `snapshot-editor` tools provided with the firecracker release:

`rebase-snap` (deprecated) example:

```bash
rebase-snap --base-file path/to/base --diff-file path/to/layer
```

`snapshot-editor` example:

```bash
snapshot-editor edit-memory rebase \
     --memory-path path/to/base \
     --diff-path path/to/layer
```

After executing the command above, the base would be a resumable snapshot memory
file describing the state of the memory at the moment of creation of the layer.
More layers which were created later can be merged on top of this base.

This process needs to be repeated for each layer until the one describing the
desired memory state is merged on top of the base, which is constantly updated
with information from previously merged layers. Please note that users should
not merge state files which resulted from `/snapshot/create` API calls and they
should use the state file created in the same call as the memory file which was
merged last on top of the base.

#### Creating full snapshots

For creating a full snapshot, you can use the following API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/snapshot/create' \
    -H  'Accept: application/json' \
    -H  'Content-Type: application/json' \
    -d '{
            "snapshot_type": "Full",
            "snapshot_path": "./snapshot_file",
            "mem_file_path": "./mem_file",
    }'
```

Details about the required and optional fields can be found in the
[swagger definition](../../src/firecracker/swagger/firecracker.yaml).

*Note*: If the files indicated by `snapshot_path` and `mem_file_path` don't
exist at the specified paths, then they will be created right before generating
the snapshot. If they exist, the files will be truncated and overwritten.

**Prerequisites**: The microVM is `Paused`.

**Effects**:

- _on success_:

  - The file indicated by `snapshot_path` (e.g. `/path/to/snapshot_file`)
    contains the devices' model state and emulation state. The one indicated by
    `mem_file_path`(e.g. `/path/to/mem_file`) contains a full copy of the guest
    memory.
  - The generated snapshot files are immediately available to be used (current
    process releases ownership). At this point, the block devices backing files
    should be backed up externally by the user. Please note that block device
    contents are only guaranteed to be committed/flushed to the host FS, but not
    necessarily to the underlying persistent storage (could still live in host
    FS cache).
  - If diff snapshots were enabled, the snapshot creation resets then the
    dirtied page bitmap and marks all pages clean (from a diff snapshot point of
    view).

- _on failure_: no side-effects.

**Notes**:

- The separate block device file components of the snapshot have to be handled
  by the user.

#### Creating diff snapshots

For creating a diff snapshot, you should use the same API command, but with
`snapshot_type` field set to `Diff`.

*Note*: If not specified, `snapshot_type` is by default `Full`.

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/snapshot/create' \
    -H  'Accept: application/json' \
    -H  'Content-Type: application/json' \
    -d '{
            "snapshot_type": "Diff",
            "snapshot_path": "./snapshot_file",
            "mem_file_path": "./mem_file",
    }'
```

**Prerequisites**: The microVM is `Paused`.

*Note*: On a fresh microVM, `track_dirty_pages` field should be set to `true`,
when configuring the `/machine-config` resource, while on a snapshot loaded
microVM, `enable_diff_snapshots` from `PUT /snapshot/load`request body, should
be set.

**Effects**:

- _on success_:
  - The file indicated by `snapshot_path` contains the devices' model state and
    emulation state, same as when creating a full snapshot. The one indicated by
    `mem_file_path` contains this time a **diff copy** of the guest memory; the
    diff consists of the memory pages which have been dirtied since the last
    snapshot creation or since the creation of the microVM, whichever of these
    events was the most recent.
  - All the other effects mentioned in the **Effects** paragraph from **Creating
    full snapshots** section apply here.
- _on failure_: no side-effects.

*Note*: This is an example of an API command that enables dirty page tracking:

```bash
curl --unix-socket /tmp/firecracker.socket -i  \
    -X PUT 'http://localhost/machine-config' \
    -H 'Accept: application/json'            \
    -H 'Content-Type: application/json'      \
    -d '{
            "vcpu_count": 2,
            "mem_size_mib": 1024,
            "smt": false,
            "track_dirty_pages": true
    }'
```

Enabling this support enables KVM dirty page tracking, so it comes at a cost
(which consists of CPU cycles spent by KVM accounting for dirtied pages); it
should only be used when needed.

Creating a snapshot will **not** influence state, will **not** stop or end the
microVM, it can be used as before, so the microVM can be resumed if you still
want to use it. At this point, in case you plan to continue using the current
microVM, you should make sure to also copy the disk backing files.

### Resuming the microVM

You can resume the microVM by sending the following API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PATCH 'http://localhost/vm' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
            "state": "Resumed"
    }'
```

**Prerequisites**: The microVM is `Paused`. Successive calls of this request are
ignored (microVM remains in the running state). **Effects**:

- _on success_: microVM is guaranteed to be `Resumed`.
- _on failure_: no side-effects.

### Loading snapshots

If you want to load a snapshot, you can do that only **before** the microVM is
configured (the only resources that can be configured prior are the Logger and
the Metrics systems) by sending the following API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/snapshot/load' \
    -H  'Accept: application/json' \
    -H  'Content-Type: application/json' \
    -d '{
            "snapshot_path": "./snapshot_file",
            "mem_backend": {
                "backend_path": "./mem_file",
                "backend_type": "File"
            },
            "enable_diff_snapshots": true,
            "resume_vm": false
    }'
```

The `backend_type` field represents the memory backend type used for loading the
snapshot. Accepted values are:

- `File` - rely on the kernel to handle page faults when loading the contents of
  the guest memory file into memory.
- `Uffd` - use a dedicated user space process to handle page faults that occur
  for the guest memory range. Please refer to
  [this](handling-page-faults-on-snapshot-resume.md) for more details on
  handling page faults in the user space.

The meaning of `backend_path` depends on the `backend_type` chosen:

- if using `File`, then `backend_path` should contain the path to the snapshot's
  memory file to be loaded.
- when using `Uffd`, `backend_path` refers to the path of the unix domain socket
  used for communication between Firecracker and the user space process that
  handles page faults.

When relying on the OS to handle page faults, the command below is also
accepted. Note that `mem_file_path` field is currently under the deprecation
policy. `mem_file_path` and `mem_backend` are mutually exclusive, therefore
specifying them both at the same time will return an error.

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/snapshot/load' \
    -H  'Accept: application/json' \
    -H  'Content-Type: application/json' \
    -d '{
            "snapshot_path": "./snapshot_file",
            "mem_file_path": "./mem_file",
            "enable_diff_snapshots": true,
            "resume_vm": false
    }'
```

Details about the required and optional fields can be found in the
[swagger definition](../../src/firecracker/swagger/firecracker.yaml).

**Prerequisites**: A full memory snapshot and a microVM state file **must** be
provided. The disk backing files, network interfaces backing TAPs and/or vsock
backing socket that were used for the original microVM's configuration should be
set up and accessible to the new Firecracker process (in which the microVM is
resumed). These host-resources need to be accessible at the same relative paths
to the new Firecracker process as they were to the original one.

**Effects:**

- _on success_:
  - The complete microVM state is loaded from snapshot into the current
    Firecracker process.
  - It then resets the dirtied page bitmap and marks all pages clean (from a
    diff snapshot point of view).
  - The loaded microVM is now in the `Paused` state, so it needs to be resumed
    for it to run.
  - The memory file (pointed by `backend_path` when using `File` backend type,
    or pointed by `mem_file_path`) **must** be considered immutable from
    Firecracker and host point of view. It backs the guest OS memory for read
    access through the page cache. External modification to this file corrupts
    the guest memory and leads to undefined behavior.
  - The file indicated by `snapshot_path`, that is used to load from, is
    released and no longer used by this process.
  - If `enable_diff_snapshots` is set, then diff snapshots can be taken
    afterwards.
  - If `resume_vm` is set, the vm is automatically resumed if load is
    successful.
- _on failure_: A specific error is reported and then the current Firecracker
  process is ended (as it might be in an invalid state).

*Notes*: Please, keep in mind that only by setting to true
`enable_diff_snapshots`, when loading a snapshot, or `track_dirty_pages`, when
configuring the machine on a fresh microVM, you can then create a `diff`
snapshot. Also, `track_dirty_pages` is not saved when creating a snapshot, so
you need to explicitly set `enable_diff_snapshots` when sending
`LoadSnapshot`command if you want to be able to do diff snapshots from a loaded
microVM. Another thing that you should be aware of is the following: if a fresh
microVM can create diff snapshots, then if you create a **full** snapshot, the
memory file contains the whole guest memory, while if you create a **diff** one,
that file is sparse and only contains the guest dirtied pages. With these in
mind, some possible snapshotting scenarios are the following:

- `Boot from a fresh microVM` -> `Pause` -> `Create snapshot` -> `Resume` ->
  `Pause` -> `Create snapshot` -> ... ;
- `Boot from a fresh microVM` -> `Pause` -> `Create snapshot` -> `Resume` ->
  `Pause` -> `Resume` -> ... -> `Pause` -> `Create snapshot` -> ... ;
- `Load snapshot` -> `Resume` -> `Pause` -> `Create snapshot` -> `Resume` ->
  `Pause` -> `Create snapshot` -> ... ;
- `Load snapshot` -> `Resume` -> `Pause` -> `Create snapshot` -> `Resume` ->
  `Pause` -> `Resume` -> ... -> `Pause` -> `Create snapshot` -> ... ; where
  `Create snapshot` can refer to either a full or a diff snapshot for all the
  aforementioned flows.

It is also worth knowing, a microVM that is restored from snapshot will be
resumed with the guest OS wall-clock continuing from the moment of the snapshot
creation. For this reason, the wall-clock should be updated to the current time,
on the guest-side. More details on how you could do this can be found at a
[related FAQ](../../FAQ.md#my-guest-wall-clock-is-drifting-how-can-i-fix-it).

## Provisioning host disk space for snapshots

Depending on VM memory size, snapshots can consume a lot of disk space.
Firecracker integrators **must** ensure that the provisioned disk space is
sufficient for normal operation of their service as well as during failure
scenarios. If the service exposes the snapshot triggers to customers,
integrators **must** enforce proper disk quotas to avoid any DoS threats that
would cause the service to fail or function abnormally.

## Ensure continued network connectivity for clones

For recommendations related to continued network connectivity for multiple
clones created from a single Firecracker microVM snapshot please see
[this doc](network-for-clones.md).

## Snapshot security and uniqueness

When snapshots are used in a such a manner that a given guest's state is resumed
from more than once, guest information assumed to be unique may in fact not be;
this information can include identifiers, random numbers and random number
seeds, the guest OS entropy pool, as well as cryptographic tokens. Without a
strong mechanism that enables users to guarantee that unique things stay unique
across snapshot restores, we consider resuming execution from the same state
more than once insecure.

For more information please see [this doc](random-for-clones.md)

### Usage examples

#### Example 1: secure usage (currently in dev preview)

```console
Boot microVM A -> ... -> Create snapshot S -> Terminate
                                           -> Load S in microVM B -> Resume -> ...
```

Here, microVM A terminates after creating the snapshot without ever resuming
work, and a single microVM B resumes execution from snapshot S. In this case,
unique identifiers, random numbers, and cryptographic tokens that are meant to
be used once are indeed only used once. In this example, we consider microVM B
secure.

#### Example 2: potentially insecure usage

```console
Boot microVM A -> ... -> Create snapshot S -> Resume -> ...
                                           -> Load S in microVM B -> Resume -> ...
```

Here, both microVM A and B do work starting from the state stored in snapshot S.
Unique identifiers, random numbers, and cryptographic tokens that are meant to
be used once may be used twice. It doesn't matter if microVM A is terminated
before microVM B resumes execution from snapshot S or not. In this example, we
consider both microVMs insecure as soon as microVM A resumes execution.

#### Example 3: potentially insecure usage

```console
Boot microVM A -> ... -> Create snapshot S -> ...
                                           -> Load S in microVM B -> Resume -> ...
                                           -> Load S in microVM C -> Resume -> ...
                                           [...]
```

Here, both microVM B and C do work starting from the state stored in snapshot S.
Unique identifiers, random numbers, and cryptographic tokens that are meant to
be used once may be used twice. It doesn't matter at which points in time
microVMs B and C resume execution, or if microVM A terminates or not after the
snapshot is created. In this example, we consider microVMs B and C insecure, and
we also consider microVM A insecure if it resumes execution.

### Reusing snapshotted states securely

[Virtual Machine Generation Identifier](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/virtual-machine-generation-identifier)
(VMGenID) is a virtual device that allows VM guests to detect when they have
resumed from a snapshot. It works by exposing a cryptographically random
16-bytes identifier to the guest. The VMM ensures that the value of the
identifier changes every time the VM a time shift happens in the lifecycle of
the VM, e.g. when it resumes from a snapshot.

Linux supports VMGenID since version 5.18 for systems with ACPI support. Linux
6.10 added support also for systems that use DeviceTree instead of ACPI. When
Linux detects a change in the identifier, it uses its value to reseed its
internal PRNG.

Firecracker supports VMGenID device both on x86 and Aarch64 platforms.
Firecracker will always enable the device. During snapshot resume, Firecracker
will update the 16-byte generation ID and inject a notification in the guest
before resuming its vCPUs.

As a result, guests that run Linux versions >= 5.18 will re-seed their in-kernel
PRNG upon snapshot resume. User space applications can rely on the guest kernel
for randomness. State other than the guest kernel entropy pool, such as unique
identifiers, cached random numbers, cryptographic tokens, etc **will** still be
replicated across multiple microVMs resumed from the same snapshot. Users need
to implement mechanisms for ensuring de-duplication of such state, where needed.

## Vsock device limitation

Vsock must be inactive during snapshot. Vsock device can break if snapshotted
while having active connections. Firecracker snapshots do not capture any
inflight network or vsock (through the linux unix domain socket backend) traffic
that has left or not yet entered Firecracker.

The above, coupled with the fact that Vsock control protocol is not resilient to
vsock packet loss, leads to Vsock device breakage when doing a snapshot while
there are active Vsock connections.

As a solution to the above issue, active Vsock connections prior to snapshotting
the VM are forcibly closed by sending a specific event called
`VIRTIO_VSOCK_EVENT_TRANSPORT_RESET`. The event is sent on `SnapshotCreate`. On
`SnapshotResume`, when the VM becomes active again, the vsock driver closes all
existing connections. Listen sockets still remain active. Users wanting to build
vsock applications that use the snapshot capability have to take this into
consideration. More details about this event can be found in the official Virtio
document [here](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.pdf),
section 5.10.6.6 Device Events.

Firecracker handles sending the `reset` event to the vsock driver, thus the
customers are no longer responsible for closing active connections.

## VMGenID device limitation

During snashot resume, Firecracker updates the 16-byte generation ID of the
VMGenID device and injects an interrupt in the guest before resuming vCPUs. If
the snapshot was taken at the very early stages of the guest kernel boot process
proper interrupt handling might not be in place yet. As a result, the kernel
might not be able to handle the injected notification and crash. We suggest to
users that they take snapshots only after the guest kernel has completed
booting, to avoid this issue.

## Snapshot compatibility across kernel versions

We have a mechanism in place to experiment with snapshot compatibility across
supported host kernel versions by generating snapshot artifacts through
[this tool](../../tools/create_snapshot_artifact) and checking devices'
functionality using
[this test](../../tests/integration_tests/functional/test_snapshot_restore_cross_kernel.py).
The test restores the snapshot and ensures that all the devices set-up (network
devices, disk, vsock, balloon and MMDS) are operational post-load.

In those tests the instance is fixed, except some combinations where we also
test across the same CPU family (Intel x86, Gravitons). In general cross-CPU
snapshots [are not supported](./versioning.md#cpu-model)

The tables below reflect the snapshot compatibility observed on the AWS
instances we support.

**all** means all currently supported Intel/AMD/ARM metal instances (m6g, m7g,
m5n, c5n, m6i, m6a). It does not mean cross-instance, i.e. a snapshot taken on
m6i won't work on an m6g instance.

| *CPU family* | *taken on host kernel* | *restored on host kernel* | *working?* |
| ------------ | ---------------------- | ------------------------- | ---------- |
| **all**      | 5.10                   | 6.1                       | Y          |
| **all**      | 6.1                    | 5.10                      | Y          |

What doesn't work:

- Graviton 4.14 \<-> 5.10 does not restore due to register incompatibility.
- Intel 5.10 -> 4.14 does not restore because unresponsive net devices
- AMD m6a 5.10 -> 4.14 does not restore due to mismatch in MSRs
