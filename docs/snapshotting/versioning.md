# Firecracker snapshot versioning

This document describes how Firecracker persists microVM state into Firecracker
snapshots. It describes the snapshot format, encoding, compatibility and
limitations.

## Introduction

Firecracker uses the serde crate [1] along with the bincode [2] format to
serialize its state into Firecracker snapshots. Firecracker snapshots have
versions that are independent of Firecracker versions. Each Firecracker version
declares support for a specific snapshot data format version. When creating a
snapshot, Firecracker will use the supported snapshot format version. When
loading a snapshot, Firecracker will check that format of the snapshot file is
compatible with the snapshot version Firecracker supports.

## Overview

Firecracker persists the microVM state as 2 separate objects:

- a **guest memory** file
- a **microVM state** file.

*The block devices attached to the microVM are not considered part of the state
and need to be managed separately.*

### Guest memory

The guest memory file contains the microVM memory saved as a dump of all pages.

### MicroVM state

In the VM state file, Firecracker stores the internal state of the VMM (device
emulation, KVM and vCPUs) with 2 exceptions - serial emulation and vsock
backend.

While we continuously improve and extend Firecracker's features by adding new
capabilities, devices or enhancements, the microVM state file may change both
structurally and semantically with each new release.

## MicroVM state file format

A Firecracker snapshot has the following format:

| Field    | Bits | Description                                               |
| -------- | ---- | --------------------------------------------------------- |
| magic_id | 64   | Firecracker snapshot and architecture (x86_64/aarch64).   |
| version  | M    | The snapshot data format version (`MAJOR.MINOR.PATCH`)    |
| state    | N    | Bincode blob containing the microVM state.                |
| crc      | 64   | Optional CRC64 sum of magic_id, version and state fields. |

The snapshot format has its own version encoded in the snapshot file itself
after the snapshot's `magic_id`. The snapshot format version is independent of
the Firecracker version and it is of the form `MAJOR.MINOR.PATCH`.

Currently, Firecracker uses the
[Serde bincode encoder](https://github.com/servo/bincode) for serializing the
microVM state. The encoding format that bincode uses does not allow backwards
compatible changes in the state, so essentially every change in the microVM
state description will result in bump of the format's `MAJOR` version. If the
needs arises, we will look into alternative formats that allow more flexibility
with regards to backwards compatibility. If/when this happens, we will define
how changes in the snapshot format reflect to changes in its `MAJOR.MINOR.PATCH`
version.

## VM state encoding

During research and prototyping we considered multiple storage formats. The
criteria used for comparing these are: performance, size, rust support,
specification, versioning support, community and tooling. Performance, size and
Rust support are hard requirements while all others can be the subject of trade
offs. More info about this comparison can be found
[here](https://github.com/firecracker-microvm/firecracker/blob/9d427b33d989c3225d874210f6c2849465941dc0/docs/snapshotting/design.md#snapshot-format).

Key benefits of using *bincode*:

- Minimal snapshot size overhead
- Minimal CPU overhead
- Simple implementation

The current implementation relies on the
[Serde bincode encoder](https://github.com/servo/bincode).

## Snapshot compatibility

### Host kernel

Snapshots can be saved and restored on the same kernel version without any
issues. There might be issues when restoring snapshots created on different host
kernel version even when using the same Firecracker version.

SnapshotCreate and SnapshotLoad operations across different host kernels is
considered unstable in Firecracker as the saved KVM state might have different
semantics on different kernels.

### Device model

The current Firecracker devices are backwards compatible up to the version that
introduces them. Ideally this property would be kept over time, but there are
situations when a new version of a device exposes new features to the guest that
do not exist in an older version. In such cases restoring a snapshot at an older
version becomes impossible without breaking the guest workload.

The microVM state file links some resources that are external to the snapshot:

- tap devices by device name,
- block devices by block file path,
- vsock backing Unix domain socket by socket name.

To successfully restore a microVM one should check that:

- tap devices are available, their names match their original names since these
  are the values saved in the microVM state file, and they are accessible to the
  Firecracker process where the microVM is being restored,
- block devices are set up at their original relative or absolute paths with the
  proper permissions, as the Firecracker process with the restored microVM will
  attempt to access them exactly as they were accessed in the original
  Firecracker process,
- the vsock backing Unix domain socket is available, its name matches the
  original name, and it is accessible to the new Firecracker process.

### CPU model

Firecracker microVMs snapshot functionality is available for Intel/AMD/ARM64 CPU
models that support the hardware virtualizations extensions, more details are
available [here](../../README.md#supported-platforms). Snapshots are not
compatible across CPU architectures and even across CPU models of the same
architecture. They are only compatible if the CPU features exposed to the guest
are an invariant when saving and restoring the snapshot. The trivial scenario is
creating and restoring snapshots on hosts that have the same CPU model.

Restoring from an Intel snapshot on AMD (or vice-versa) is not supported.

It is important to note that guest workloads can still execute instructions that
are being [masked](../cpu_templates/cpu-templates.md) by CPUID and restoring and
saving of such workloads will lead to undefined result. Firecracker retrieves
the state of a discrete list of MSRs from KVM, more specifically, the MSRs
corresponding to the guest exposed features.

## Implementation

The microVM state file format is implemented in the
[snapshot crate](../../src/vmm/src/snapshot/mod.rs) in the Firecracker
repository. All Firecracker devices implement the
[Persist](../../src/vmm/src/snapshot/persist.rs) trait which exposes an
interface that enables creating from and saving to the microVM state.

[1]: https://serde.rs
[2]: https://github.com/bincode-org/bincode
