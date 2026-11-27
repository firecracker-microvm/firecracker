# SharedMemfd: sharing guest memory with another process

> [!WARNING]
>
> The `SharedMemfd` memory backend is in developer preview. The API described
> here may change in incompatible ways before it is stabilised.

`SharedMemfd` lets a process of yours read and write the memory of a running
microVM directly.

## Why

Guest memory normally belongs to the Firecracker process alone. To get it out,
you take a snapshot with `PUT /snapshot/create`, which needs the microVM paused
and writes memory to a file. To put it in, you restore, from such a file or page
by page through a
[UFFD page fault handler](handling-page-faults-on-snapshot-resume.md).

That is enough for occasional snapshots. It is not enough for tooling that moves
guest memory itself, for example:

- **Live migration**, pre-copy or post-copy: memory has to be copied to the
  destination while the guest runs, not while it is paused.
- **Snapshots without the disk round trip**: the tool captures memory straight
  from the guest and sends it wherever it wants, instead of having Firecracker
  write a memory file first.

Both start with access to guest memory from outside Firecracker. `SharedMemfd`
is that first building block, and it is what this document describes. The APIs
planned on top of it are in the
[design discussion](https://github.com/firecracker-microvm/firecracker/discussions/6269).

## How it works

1. You run a process, called *the backend* in this document, that listens on a
   Unix domain socket.
1. You tell Firecracker about it, at boot or on restore.
1. Firecracker puts all guest memory in one memfd (a file that lives in RAM) and
   sends its file descriptor to the backend, once, before the guest runs.
1. The backend reads and writes the memfd. Firecracker maps the same memfd, so
   the backend and the guest see the same bytes.

|                      | At boot               | On restore                                         |
| :------------------- | :-------------------- | :------------------------------------------------- |
| Configured in        | `machine-config`      | `snapshot/load`                                    |
| The backend receives | the memfd             | a userfaultfd and the memfd                        |
| Memory is filled by  | the guest, as it runs | the backend, serving page faults from the snapshot |

On restore, `SharedMemfd` is the `Uffd` backend plus the memfd: the backend is a
page fault handler that can also see the memory it populates.

## Using it

### At boot

Set `mem_backend` in `PUT /machine-config`, `PATCH /machine-config` or the JSON
configuration file:

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

Only `SharedMemfd` is accepted here; `File` and `Uffd` describe how memory is
populated on a restore. A `PUT` without the field, or a `PATCH` with
`"mem_backend": null`, removes the backend.

### On restore

Give `SharedMemfd` as the backend of `PUT /snapshot/load`:

```json
{
  "snapshot_path": "/path/vmstate",
  "mem_backend": {
    "backend_type": "SharedMemfd",
    "backend_path": "/run/backend.sock"
  }
}
```

Everything the
[page fault handler document](handling-page-faults-on-snapshot-resume.md) says
about serving page faults, including balloon `remove` events, applies.

The backend is chosen per microVM and is not recorded in the snapshot: a
snapshot taken from a microVM with a memory backend restores with `File` or
`Uffd`, and the other way around.

### Reading the configuration back

`GET /machine-config` and `GET /vm/config` report the backend in `mem_backend`:
the one set in the machine configuration after a boot, and the one given to
`PUT /snapshot/load` after a restore.

The rest of this document is reference material for writing a backend.

## The handshake

Firecracker describes guest memory to the backend in a single message. It is the
message a page fault handler gets with `backend_type: Uffd`; only the attached
file descriptors differ.

The message is sent once guest memory is set up and before any vCPU runs: during
`PUT /snapshot/load` on a restore, and as the last step of `InstanceStart` (or
of starting with `--config-file`) on a boot. If Firecracker cannot connect to
the backend, that request fails. A failed `InstanceStart` can be retried. If
anything fails after the message was sent, Firecracker exits and the backend
sees its connection close.

### The socket

The backend listens on a `SOCK_STREAM` Unix domain socket, and Firecracker
connects to `backend_path` (relative to its chroot when jailed).

After the message, Firecracker neither reads nor writes the socket, but keeps it
open until it exits. The backend can use the connection to learn Firecracker's
PID (`SO_PEERCRED`) and to notice that Firecracker exited (the connection
closes).

### The message

The message is one `sendmsg`: a JSON array, with the file descriptors attached
as `SCM_RIGHTS` data. Read it with one `recvmsg`. The payload is a few hundred
bytes and there are at most two descriptors. Do not wait for end of file, which
only comes when Firecracker exits.

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

The regions are the guest's physical memory regions (more than one when memory
extends past an MMIO gap), plus the virtio-mem hotplug region if there is one,
whether plugged or not. They sit one after the other in the memfd, and their
sizes add up to the size of the memfd.

### The file descriptors

| How the microVM was started                      | fds received    |
| :----------------------------------------------- | :-------------- |
| `snapshot/load` with `backend_type: File`        | N/A, no socket  |
| `snapshot/load` with `backend_type: Uffd`        | `[uffd]`        |
| `snapshot/load` with `backend_type: SharedMemfd` | `[uffd, memfd]` |
| At boot with `machine-config.mem_backend`        | `[memfd]`       |
| At boot without `machine-config.mem_backend`     | N/A, no socket  |

The userfaultfd always comes first and the memfd always comes last. This order
is part of the API. The backend knows how the microVM was started, so it should
check that it received exactly the descriptors it expects.

The userfaultfd is registered on every region in missing-page mode, with
`remove` events enabled.
[The page fault handler document](handling-page-faults-on-snapshot-resume.md)
explains how to serve it.

## Working with the memfd

The memfd holds all of guest memory, laid out like a full memory snapshot file.
Firecracker maps it `MAP_SHARED`, so the backend and the guest see the same
bytes.

- It is shmem, or hugetlbfs when the microVM uses 2 MiB pages.
- It cannot be resized (it is sealed), but it can be written, and holes can be
  punched in it. Firecracker punches holes itself when the guest gives memory
  back (balloon, free page reporting, virtio-mem unplug).
- Firecracker keeps its own descriptor, so guest memory stays valid if the
  backend exits.

### After a boot

The memfd already holds the boot payload (kernel, initrd, command line, boot
structures) when the backend receives it. From then on the guest fills it. The
backend can read and write it freely: a write changes what the guest sees.

### After a restore

The backend does what a UFFD page fault handler does, and can use the memfd on
top of that.

**Serve page faults.** Guest memory starts empty, and the backend fills it from
the snapshot's memory file:

1. Wait for an event on the userfaultfd.
1. On a page fault, find the region that contains the faulting address, and copy
   the page from the memory file, at `offset + (address - base_host_virt_addr)`,
   with `UFFDIO_COPY`.
1. On a `remove` event, handle it as
   [the page fault handler document](handling-page-faults-on-snapshot-resume.md)
   describes.

The backend can also populate pages before the guest asks for them, with
`UFFDIO_COPY` as well.

**Use the memfd.** Once a page is populated, it is in the memfd, at the same
offset as in the memory file. The backend can read and write it there, as after
a boot.

**Leave unpopulated pages to the userfaultfd.** A page that is not populated yet
is a hole in the memfd. Populate it with `UFFDIO_COPY`, never by writing the
memfd or by touching it through a mapping of your own: that fills the hole
without the userfaultfd knowing. The guest then reads the wrong content, or a
thread waiting on a fault for that page is never woken up. For the same reason,
do not copy the whole memory file into the memfd.

## Huge pages

Guest memory is a `MAP_SHARED` mapping, and page faults on it are somewhat
slower than on anonymous memory. Hugetlbfs (`huge_pages: 2M`) removes almost all
of that cost. Transparent huge pages remove only part of it, and only if the
host's `shmem_enabled` setting allows them.

On a restore, transparent huge pages are unsafe on hosts before Linux 6.4.
`khugepaged` can collapse a 2 MiB range of the memfd that is only partly
populated and fill the missing pages with zeros, so the guest reads zeros
without a page fault. This was
[fixed](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ac492b9c70cac4d887e9dce4410b1d521851e142)
in Linux 6.4 and not backported to 5.10 or 6.1. On such hosts, for a restore
with `SharedMemfd`:

- do not restore with `huge_pages` set to `Transparent`;
- keep `shmem_enabled` at `never` or `advise`;
- do not `madvise(MADV_HUGEPAGE)` a mapping of the memfd in the backend.

## Example backend

The example handlers in
[`src/firecracker/examples/uffd/`](../../src/firecracker/examples/uffd/) accept
every row of the table above. They recognise the memfd as a regular file, which
a userfaultfd is not. A handler started as `<handler> <socket path>`, without a
memory file, is the backend of a boot. The example handlers only hold on to the
memfd; they do nothing with it.

## Limitations

- **No restore from a file with sharing.** On a restore with `SharedMemfd`,
  memory is always populated through the userfaultfd.
- **Firecracker does not watch the backend.** If the backend of a boot dies, the
  microVM keeps running. If the backend of a restore dies, nobody serves page
  faults: the next fault blocks the thread that takes it, a vCPU or one of
  Firecracker's own. A full snapshot then hangs on the first page that is not
  populated (a diff snapshot only reads pages that are already there, and still
  works), and discards (balloon, free page reporting, virtio-mem unplug) block
  until someone reads the `remove` event.
- **Diff snapshots miss what the backend writes.** With `track_dirty_pages`,
  dirty page tracking only sees writes made by the guest and by Firecracker. If
  the backend writes guest memory, take full snapshots, or leave
  `track_dirty_pages` disabled: diff snapshots then include every page present
  in the memfd.
- **A full snapshot after a boot allocates all of guest memory.** Firecracker
  reads every page through its mapping of the memfd, and reading a page the
  memfd does not hold (one the guest never touched or gave back) allocates it.
  Host memory usage grows to the full size of guest memory, charged to
  Firecracker's memory cgroup, and the memfd has no holes left. After a restore,
  a full snapshot faults every page in through the backend instead, as it does
  with `Uffd`.
- **No vhost-user hotplug after a restore.** A vhost-user server would map the
  memfd without the userfaultfd and read pages that are not populated yet as
  zeros.
- **Memory accounting is split.** Pages populated with `UFFDIO_COPY` are charged
  to Firecracker's memory cgroup. Pages the backend allocates by writing the
  memfd, or through a mapping of its own, are charged to the backend's.
- **The backend's descriptor keeps guest memory allocated** after Firecracker
  exits, until the backend closes it. A handler written for `Uffd` that expects
  a single descriptor may still get the memfd installed in its file descriptor
  table (it depends on the control message space its `recvmsg` provides).
  Receive both descriptors, and close the memfd if you do not use it.
- **Not for Nitro Sandboxes.** A [Nitro Sandbox](../nitro-sandboxes/README.md)
  rejects `mem_backend` at `InstanceStart`: its guest memory is donated by the
  Nitro Enclaves driver.
- **Jailer:** the `fsize` resource limit must cover the whole memfd, at boot and
  on a restore. See [the jailer document](../jailer.md).
