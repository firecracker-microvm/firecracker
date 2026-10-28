# Shared memfd: guest memory in the hands of an external process

> [!WARNING]
>
> The `SharedMemfd` memory backend is in developer preview. The API described
> here may change in incompatible ways before it is stabilised.

`SharedMemfd` is an advanced feature for users looking for a custom or
high-performance snapshot, restore or live-migration solution.

## What it is

`SharedMemfd` is a `backend_type` for `mem_backend`, next to `File` and `Uffd`.
It is similar to the `Uffd` backend with two important distinctions:

- Firecracker allocates guest memory as a single `memfd` and hands it to the
  backend via Unix domain socket as part of the handshake
- it can also be used at boot, in which case there's no UFFD

When `SharedMemfd` is used, the backend can read (and write) guest memory
directly, without going through Firecracker.

When used on VM restore, the `SharedMemfd` backend is a
[UFFD page fault handler](handling-page-faults-on-snapshot-resume.md) that
receives one more file descriptor: everything that document says about serving
faults, including the handling of balloon `remove` events, applies unchanged.

## The handshake

Firecracker hands guest memory to the backend with one message on a Unix domain
socket. The message is sent once, after guest memory is set up and before any
vCPU runs. It is the same message Firecracker sends to a page fault handler when
restoring with `backend_type: Uffd`; a backend just receives one more file
descriptor with it.

### The socket

The backend creates and listens on a `SOCK_STREAM` Unix domain socket which is
then passed to Firecracker (via the config file, `PUT /machine-config` or
`PUT /snapshot/load`). Firecracker then connects to the path given in the
request (relative to its chroot when jailed) and sends the handshake message. If
nobody is listening, the operation fails: `PUT /snapshot/load` on a restore,
`InstanceStart` (or the process start with `--config-file`) on a boot.

After that, Firecracker never reads from or writes to the socket, and keeps it
open until it exits. The backend can use the connection to learn Firecracker's
PID with `SO_PEERCRED`, and to notice that Firecracker has exited when the
connection closes. Anything the backend sends on it is ignored.

### The message

A single `sendmsg` with a JSON array as payload and the file descriptors
attached as `SCM_RIGHTS` data. Read it with one `recvmsg`. There is no framing;
the payload is a few hundred bytes and there are at most two descriptors. Do not
wait for end of file: it only comes when Firecracker exits.

The array has one entry per guest memory region, in guest address order:

```json
[
  {
    "base_host_virt_addr": 140160296779776,
    "size": 3221225472,
    "offset": 0,
    "page_size": 4096,
    "page_size_kib": 4096
  },
  {
    "base_host_virt_addr": 140163518005248,
    "size": 1073741824,
    "offset": 3221225472,
    "page_size": 4096,
    "page_size_kib": 4096
  }
]
```

| Field                 | Meaning                                                                                             |
| :-------------------- | :-------------------------------------------------------------------------------------------------- |
| `base_host_virt_addr` | Address of the region in Firecracker's address space. Page fault events use it; the memfd does not. |
| `size`                | Region size in bytes.                                                                               |
| `offset`              | Offset of the region in the memfd. It is also its offset in a memory snapshot file.                 |
| `page_size`           | Page size in bytes: 4096, or 2097152 (2 MiB) with hugetlbfs.                                        |
| `page_size_kib`       | Deprecated copy of `page_size`. The value is in bytes despite the name. Will be removed in 2.0.     |

The regions are the guest's physical memory regions (one region, or two on x86
when memory extends past the 32-bit MMIO gap) and the virtio-mem hotplug region
if there is one, plugged or not. They are contiguous in the memfd, and their
sizes add up to the size of the memfd.

### The file descriptors

| How the microVM was started                      | fds received    |
| :----------------------------------------------- | :-------------- |
| `snapshot/load` with `backend_type: File`        | N/A, no socket  |
| `snapshot/load` with `backend_type: Uffd`        | `[uffd]`        |
| `snapshot/load` with `backend_type: SharedMemfd` | `[uffd, memfd]` |
| At boot with `machine-config.mem_backend`        | `[memfd]`       |
| At boot without `machine-config.mem_backend`     | N/A, no socket  |

The userfaultfd comes first and the memfd last. The order of the fds is part of
the API contract. A properly architected backend should be aware of
Firecracker's lifecycle and can always assert the exact fds it expects.

The memfd is all the guest memory, laid out like a full memory snapshot file:
region *n* starts at its `offset`. Firecracker maps it `MAP_SHARED`, so reading
it (with `pread`, `copy_file_range`, or a mapping of your own) gives the same
bytes the guest sees, and writing it changes what the guest sees. It is sealed
against resizing but not against writing or punching holes; Firecracker itself
punches holes when the guest releases memory (balloon, free page reporting,
virtio-mem unplug). It is shmem, or hugetlbfs when the microVM uses 2M pages.
Firecracker keeps its own descriptor, so a backend exiting does not invalidate
guest memory. (A backend that was serving page faults and exits does leave the
guest stuck on the next fault, but that is the userfaultfd, not the memfd.)

The userfaultfd, when present, is registered on every region in missing-page
mode with `remove` events enabled. How to serve it is described in
[the page fault handler document](handling-page-faults-on-snapshot-resume.md).
The regions it reports are the same as in the message.

### After the handshake

On a fresh boot, Firecracker writes the boot payload (kernel, initrd, command
line, boot structures) into the otherwise empty memfd after the handshake and
before any vCPU runs; from then on the guest fills it. On a restore, the backend
serves page faults from the snapshot file, and the memfd fills with what it
populates and what the guest writes.

Sharing memory this way has a cost: guest memory is a `MAP_SHARED` mapping; page
faults on it are somewhat slower than on anonymous memory. Hugetlbfs mitigates
the performance loss very effectively. Transparent huge pages depend on the
host's `shmem_enabled` setting, and only partially mitigate the performance
loss.

## API

### Attaching a backend at boot: `PUT /machine-config`

```json
{
  "vcpu_count": 2,
  "mem_size_mib": 1024,
  "mem_backend": {
    "backend_type": "SharedMemfd",
    "backend_path": "/run/backend.sock"
  }
}
```

Only `SharedMemfd` is accepted here (`File` and `Uffd` describe how memory is
*populated* on restore and have no meaning at boot). The field is also accepted
in the JSON configuration file. When set, guest memory is one memfd and the
handshake carrying `[memfd]` is performed during `InstanceStart`, after all
memory regions have been mapped and before any vCPU runs. Failing to connect to
`backend_path` fails the boot.

### Attaching a backend at restore: `PUT /snapshot/load`

```json
{
  "snapshot_path": "/path/vmstate",
  "mem_backend": {
    "backend_type": "SharedMemfd",
    "backend_path": "/run/backend.sock"
  }
}
```

`SharedMemfd` behaves like `Uffd`: a uffd is created, registered on the
(memfd-backed) guest memory, and the handshake carries `[uffd, memfd]`. The
backend serves page faults exactly as a UFFD handler does.

The choice is per instance and is **not** recorded in the snapshot: a snapshot
made with a memory backend restores fine with `File` or `Uffd`, and vice versa.

## Example backend

The example handlers in
[`src/firecracker/examples/uffd/`](../../src/firecracker/examples/uffd/) take
the `backend_type` they are attached with as their first argument, and expect
the fds of the matching row above. Started as
`<handler> SharedMemfd <socket path>`, without a memory file, a handler expects
the boot handshake (`[memfd]`); with a memory file, the restore handshake
(`[uffd, memfd]`). Started as `<handler> Uffd <socket path> <memory file>`, it
expects `[uffd]`. They only hold on to the memfd.

## Limitations

- Guest memory is a `MAP_SHARED` mapping, which results in slower page faults.
  Please benchmark your use-case before enabling this feature. With hugetlbfs,
  the regression effectively disappears.
- Restoring with a memory backend always populates memory through the uffd.
  Populating from a snapshot file while sharing memory (the `File` backend's
  behaviour) is not offered.
- Firecracker does not monitor the backend. Killing it leaves the microVM
  running, and, in case of a restore, with nobody to serve page faults.
- Firecracker cannot know nor control what the backend or a vhost-user server
  writes to guest memory.
