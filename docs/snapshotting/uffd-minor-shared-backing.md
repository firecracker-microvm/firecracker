# UFFD minor-fault registration against a shared read-only backing (RFC)

> [!WARNING]
>
> This is an **RFC / developer preview**. The API and behaviour described here
> may change in incompatible ways, and the code does not yet build against the
> pinned `userfaultfd = "0.9.0"` crate (see "Status" at the end). It exists to
> make the design concrete and to drive the API decision in
> [discussion #6269](https://github.com/firecracker-microvm/firecracker/discussions/6269).

## Problem

When `N` microVMs resume from the **same** memory snapshot (clone fan-out,
RL-style rollouts, large same-template fleets), today's UFFD restore path backs
each one with a **private anonymous** mapping and serves missing faults with
`UFFDIO_COPY`. Every VM therefore gets its **own physical copy** of pages that
are byte-identical at resume time. For a template with guest RAM `M`, host
memory for its live clones is `≈ N·M`.

This is a different axis from the migration / live-fork use-cases already in
#6269: those optimise the capture and transfer of **one** VM's memory; this
optimises the **sharing** of identical memory across **many** VMs.

## Proposed behaviour

Add an **opt-in** mode on the `Uffd` restore backend that, instead of private
anonymous memory:

1. Backs guest regions with a caller-provided, **read-only** file mapped
   `MAP_SHARED` (shmem/memfd, or hugetlbfs where the kernel supports minor
   faults on it), laid out like a memory snapshot file.
2. Builds the uffd requesting the minor feature for the backing type
   (`UFFD_FEATURE_MINOR_SHMEM` / `UFFD_FEATURE_MINOR_HUGETLBFS`) and registers
   each region `UFFDIO_REGISTER_MODE_MINOR` (optionally `| MODE_WP`).
3. Carries the registration mode in the handshake
   (`GuestRegionUffdMapping.registration_mode`) so the external handler resolves
   a minor fault with `UFFDIO_CONTINUE` rather than `UFFDIO_COPY`.

`N` VMMs that map the **same inode** this way share **one** page-cache copy, so
`UFFDIO_CONTINUE` resolves each VM's minor fault against that single copy.
Untouched pages stay shared; host memory drops from `≈ N·M` toward
`≈ M + N·M·(1−r)`, where `r` is the fraction of pages still untouched (high
early in a clone's life). The per-fault `memcpy` also disappears.

Everything else — Firecracker owns registration, an external process owns fault
resolution — is unchanged. This only adds a registration mode and a backing
option; it does not change the plain `Uffd` or `File` paths.

## API

A new, optional, defaulted field on the `Uffd` memory backend of
`PUT /snapshot/load`:

```json
{
  "snapshot_path": "/path/vmstate",
  "mem_backend": {
    "backend_type": "Uffd",
    "backend_path": "/run/uffd.sock",
    "shared_backing_path": "/srv/snapshots/tmpl-A/memory",
    "shared_backing_wp": true
  }
}
```

- `shared_backing_path` (optional): a read-only backing shared across VMMs
  restored from the **same** snapshot — the snapshot memory file on shared
  storage, or a preloaded `/proc/self/fd/<n>`. When present, Firecracker maps it
  `MAP_SHARED` read-only and registers guest memory `MODE_MINOR`. **Absent, the
  path is byte-for-byte today's behaviour** (private anonymous, MISSING,
  `UFFDIO_COPY`).
- `shared_backing_wp` (optional, default `false`): register
  `MODE_MINOR | MODE_WP`, so a guest write takes a WP fault and the handler can
  diverge the page per-VM. Ignored unless `shared_backing_path` is set.

The choice is per instance and is **not** recorded in the snapshot.

### Handshake

`GuestRegionUffdMapping` gains a `registration_mode` field
(`missing` | `minor` | `minor_wp`), `#[serde(default)] = missing`. An old
handler, or an old Firecracker talking to a new handler, both keep the current
behaviour, so the handshake stays backward-compatible.

## Isolation model (must be designed in, not bolted on)

Because physical pages are shared across VMs, the discard path must be handled
with care:

- `pages_to_discard` and any `MADV_REMOVE` / `UFFD` `remove` event (balloon,
  free-page reporting, virtio-mem unplug) must act on a **per-VM private
  overlay**, never on the shared read-only backing — otherwise one tenant's
  discard punches holes in pages other VMs are still reading. This is exactly
  the `MAP_SHARED` memfd discard territory of #6167 / AWS bulletin 2026-169.
- Sharing must be strictly scoped to **same-snapshot, read-only, copy-on-write**
  pages, opt-in, off by default.
- On a guest write, a `MODE_MINOR | MODE_WP` region takes a WP fault; the
  handler must resolve it into a **per-VM private** page before unprotecting.
  This example ships the minor (CoW-read) resolver; per-VM write divergence is
  left as the design question for #6269.

## Relationship to the `SharedMemfd` backend (#6269 / #6362)

`SharedMemfd` (PR #6362) allocates **one memfd per instance** and shares it
**Firecracker ↔ backend** for a single VM's snapshot/migration, serving MISSING
faults with `UFFDIO_COPY`. This RFC is the **cross-VM** axis: a caller-provided
backing shared **across instances**, served with `UFFDIO_CONTINUE`. The single
assumption that has to flip is backing **ownership** — from "Firecracker
allocates the memfd per instance" to "the caller hands in a shared read-only
fd". The minor-mode + WP registration surface this RFC adds is the same one
[#5912 / #5951](https://github.com/firecracker-microvm/firecracker/pull/5951)
(WP-based capture) asked for, so one `registration_mode` API serves both.

When `SharedMemfd` lands, the merge-candidate version of this change rebases
onto its `mem_backend` structure and reuses its handshake rather than the plain
`Uffd` path edited here.

## Prior art

- CodeSandbox demonstrates the "map snapshot `MAP_SHARED`, serve minor faults
  with `UFFDIO_CONTINUE` so clones share pages CoW" pattern against Firecracker,
  on a fork (<https://codesandbox.io/blog/cloning-microvms-using-userfaultfd>).
- Cloud Hypervisor exposes a comparable "register in a caller-specified mode,
  hand the fd to an external manager" design (cloud-hypervisor#8644).

## Alternatives considered

- **Host KSM** (`MADV_MERGEABLE`): no Firecracker change, but reactive and
  non-deterministic (peak memory is still `N·M` until ksmd converges), costs
  scan CPU, merges globally with no per-tenant scoping, and has a known dedup
  timing side-channel. A stopgap, not equivalent to deterministic same-snapshot
  CoW.

## Status

- Opt-in config (`shared_backing_path` / `shared_backing_wp`), the
  `MAP_SHARED` read-only backing (`memory::shared_file_backed`), the
  `UffdRegistrationMode` handshake field, `MODE_MINOR[|WP]` registration, the
  minor-feature request with kernel-unavailable fallback, and the example
  handler's `UFFDIO_CONTINUE` resolver are all implemented on the plain `Uffd`
  path.
- **Does not build yet**: the pinned `userfaultfd = "0.9.0"` does not expose
  `register_with_mode` / `RegisterMode::MINOR|WRITE_PROTECT` / `Uffd::continue_`
  / `FeatureFlags::MINOR_SHMEM|MINOR_HUGETLBFS`. These are marked `TODO(rfc)` and
  need a crate bump (or `userfaultfd-sys` bits), to be confirmed on a networked
  Linux host.
- **Open design questions** (for #6269): per-VM write divergence on WP faults;
  discard/`MADV_REMOVE` isolation on the shared backing; hugetlbfs-minor kernel
  probing and fallback.
