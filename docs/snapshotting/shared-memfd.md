# SharedMemfd: sharing guest memory with another process

> [!WARNING]
>
> The `SharedMemfd` memory backend is in developer preview. The API described
> here may change in incompatible ways before it is stabilised.

`SharedMemfd` is for users who build their own snapshot, restore or
live-migration tooling. It gives a process of yours direct access to the guest's
memory.

## What it is

With `SharedMemfd`, Firecracker puts all guest memory in one memfd (a file that
lives in RAM) and sends its file descriptor to your process over a Unix domain
socket. This document calls your process *the backend*.

The backend can then read and write guest memory directly, without going through
Firecracker.

`SharedMemfd` is a `backend_type` for `mem_backend`, next to `File` and `Uffd`.
You can use it in two places:

- **At boot**, with `PUT /machine-config`. Memory is shared before the guest
  runs its first instruction. The backend receives only the memfd; there is
  nothing to populate, so there is no userfaultfd.
- **On restore**, with `PUT /snapshot/load`. This works like the `Uffd` backend,
  plus one file descriptor: the backend is a
  [UFFD page fault handler](handling-page-faults-on-snapshot-resume.md) that
  also receives the memfd. Everything that document says about serving page
  faults, including balloon `remove` events, still applies.

## The handshake

Firecracker tells the backend about guest memory with a single message on a Unix
domain socket. It sends the message once, after it has set up guest memory and
before any vCPU runs. It is the same message a page fault handler gets when
restoring with `backend_type: Uffd`, with one more file descriptor attached.

### The socket

The backend creates a `SOCK_STREAM` Unix domain socket and listens on it. You
give Firecracker the socket's path (in the config file, in
`PUT /machine-config`, or in `PUT /snapshot/load`). Firecracker connects to that
path (relative to its chroot when jailed) and sends the message.

If nobody is listening, the request fails: `PUT /snapshot/load` on a restore,
`InstanceStart` (or the process start with `--config-file`) on a boot.

After the message, Firecracker never reads from or writes to the socket again,
but keeps it open until it exits. The backend can use the connection to:

- learn Firecracker's PID with `SO_PEERCRED`;
- notice that Firecracker has exited, because the connection closes.

Anything the backend sends on the socket is ignored.

### The message

The message is one `sendmsg` call: a JSON array as payload, with the file
descriptors attached as `SCM_RIGHTS` data. Read it with one `recvmsg`. There is
no framing: the payload is a few hundred bytes, and there are at most two
descriptors. Do not wait for end of file; it only comes when Firecracker exits.

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

| Field                 | Meaning                                                                                                     |
| :-------------------- | :---------------------------------------------------------------------------------------------------------- |
| `base_host_virt_addr` | Where the region is in Firecracker's address space. Page fault events use this address; the memfd does not. |
| `size`                | Size of the region in bytes.                                                                                |
| `offset`              | Where the region starts in the memfd. It is the same offset as in a memory snapshot file.                   |
| `page_size`           | Page size in bytes: 4096, or 2097152 (2 MiB) with hugetlbfs.                                                |
| `page_size_kib`       | Deprecated copy of `page_size`. The value is in bytes despite the name. Will be removed in 2.0.             |

The regions are the guest's physical memory regions (one region, or two on x86
when memory extends past the 32-bit MMIO gap), plus the virtio-mem hotplug
region if there is one, whether plugged or not. The regions sit one after the
other in the memfd, and their sizes add up to the size of the memfd.

### The file descriptors

| How the microVM was started                      | fds received    |
| :----------------------------------------------- | :-------------- |
| `snapshot/load` with `backend_type: File`        | N/A, no socket  |
| `snapshot/load` with `backend_type: Uffd`        | `[uffd]`        |
| `snapshot/load` with `backend_type: SharedMemfd` | `[uffd, memfd]` |
| At boot with `machine-config.mem_backend`        | `[memfd]`       |
| At boot without `machine-config.mem_backend`     | N/A, no socket  |

The userfaultfd always comes first, and the memfd always comes last. This order
is part of the API. The backend knows how the microVM was started, so it knows
which descriptors to expect, and should check that it got exactly those.

**The memfd** holds all of guest memory, laid out like a full memory snapshot
file: region *n* starts at its `offset`. Firecracker maps it `MAP_SHARED`. That
means:

- Reading the memfd (with `pread`, `copy_file_range`, or a mapping of your own)
  gives you the bytes the guest sees right now.
- Writing the memfd changes what the guest sees.
- The memfd cannot be resized (it is sealed against that), but it can be written
  and holes can be punched in it. Firecracker punches holes itself when the
  guest gives memory back (balloon, free page reporting, virtio-mem unplug).
- It is shmem, or hugetlbfs when the microVM uses 2 MiB pages.
- Firecracker keeps its own descriptor. If the backend exits, guest memory stays
  valid. (If the backend was also serving page faults, the guest gets stuck on
  its next fault, but that is because of the userfaultfd, not the memfd.)

**The userfaultfd**, when there is one, is registered on every region in
missing-page mode, with `remove` events enabled. The regions it reports are the
same as in the message.
[The page fault handler document](handling-page-faults-on-snapshot-resume.md)
explains how to serve it.

### After the handshake

On a boot, the memfd is empty when the backend receives it. Firecracker then
writes the boot payload into it (kernel, initrd, command line, boot structures)
before any vCPU runs. From then on, the guest fills it.

On a restore, the backend serves page faults from the snapshot file, as a UFFD
handler does. The memfd fills up with the pages the backend populates and with
what the guest writes.

On a restore, the backend can also populate memory by writing the memfd directly
(with `pwrite`, or through a mapping of its own) instead of using `UFFDIO_COPY`.
Be careful when mixing the two. Both end up in the kernel's page cache, and a
missing-page fault is only raised for a page that is not in the memfd yet. So:

- A page the backend has written to the memfd never raises a page fault.
- `UFFDIO_COPY` onto a page that is already in the memfd fails with `EEXIST`.

A backend that mixes the two must treat `EEXIST` as "already populated" (the
example handlers do), and must not wait for a fault on a page it wrote itself.
This is the same for shmem and hugetlbfs.

Sharing memory has a cost. Guest memory becomes a `MAP_SHARED` mapping, and page
faults on it are somewhat slower than on anonymous memory. Hugetlbfs removes
almost all of that cost. Transparent huge pages remove only part of it, and only
if the host's `shmem_enabled` setting allows them.

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

Only `SharedMemfd` is accepted here. `File` and `Uffd` describe how memory is
populated on a restore, which means nothing at boot. The field is also accepted
in the JSON configuration file.

When set, guest memory is one memfd, and Firecracker sends the handshake with
`[memfd]` during `InstanceStart`, after it has mapped all memory regions and
before any vCPU runs. If it cannot connect to `backend_path`, the boot fails.

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

`SharedMemfd` behaves like `Uffd`: Firecracker creates a userfaultfd, registers
it on guest memory (which is now memfd-backed), and sends the handshake with
`[uffd, memfd]`. The backend serves page faults exactly as a UFFD handler does.

The choice of backend is made per microVM and is **not** recorded in the
snapshot. A snapshot taken from a microVM with a memory backend restores fine
with `File` or `Uffd`, and the other way around.

## Example backend

The example handlers in
[`src/firecracker/examples/uffd/`](../../src/firecracker/examples/uffd/) accept
every row of the table above: when there is a memfd, it is the last descriptor.
A handler started as `<handler> <socket path>`, without a memory file, is the
backend of a boot, and takes its one descriptor as the memfd. The example
handlers only hold on to the memfd; they do nothing with it.

## Limitations

- Guest memory is a `MAP_SHARED` mapping, so page faults are slower. Benchmark
  your use case before enabling this feature. With hugetlbfs, the slowdown
  effectively disappears.
- On a restore with a memory backend, memory is always populated through the
  userfaultfd. There is no way to populate from a snapshot file (what the `File`
  backend does) and share memory at the same time.
- Firecracker does not watch the backend. If the backend dies, the microVM keeps
  running, and on a restore nobody serves its page faults anymore.
- Firecracker cannot know or control what the backend, or a vhost-user server,
  writes to guest memory.
