# Backing Guest Memory by Huge Pages

Firecracker supports backing the guest memory of a VM by 2MB hugetlbfs pages.
This can be enabled by setting the `huge_pages` field of `PUT` or `PATCH`
requests to the `/machine-config` endpoint to `2M`.

Backing guest memory by huge pages can bring performance improvements for
specific workloads, due to less TLB contention and less overhead during
virtual->physical address resolution. It can also help reduce the number of
KVM_EXITS required to rebuild extended page tables post snapshot restore, as
well as improve boot times (by up to 50% as measured by Firecracker's
[boot time performance tests](../tests/integration_tests/performance/test_boottime.py))

Using hugetlbfs requires the host running Firecracker to have a pre-allocated
pool of 2M pages. Should this pool be too small, Firecracker may behave
erratically or receive the `SIGBUS` signal. This is because Firecracker uses the
`MAP_NORESERVE` flag when mapping guest memory. This flag means the kernel will
not try to reserve sufficient hugetlbfs pages at the time of the `mmap` call,
trying to claim them from the pool on-demand. For details on how to manage this
pool, please refer to the [Linux Documentation][hugetlbfs_docs].

## Huge Pages and Snapshotting

Restoring a Firecracker snapshot of a microVM backed by huge pages will also use
huge pages to back the restored guest. There is no option to flip between
regular, 4K, pages and huge pages at restore time. Furthermore, snapshots of
microVMs backed with huge pages can only be restored via UFFD. Lastly, note that
even for guests backed by huge pages, differential snapshots will always track
write accesses to guest memory at 4K granularity.

When restoring snapshots via UFFD, Firecracker will send the configured page
size (in KiB) for each memory region as part of the initial handshake, as
described in our documentation on
[UFFD-assisted snapshot-restore](snapshotting/handling-page-faults-on-snapshot-resume.md).

## Known Limitations

Currently, hugetlbfs support is mutually exclusive with the following
Firecracker features:

- Memory Ballooning via the [Balloon Device](./ballooning.md)

## FAQ

### Why does Firecracker not offer a transparent huge pages (THP) setting?

Firecracker's guest memory is memfd based. Linux (as of 6.1) does not offer a
way to dynamically enable THP for such memory regions. Additionally, UFFD does
not integrate with THP (no transparent huge pages will be allocated during
userfaulting). Please refer to the [Linux Documentation][thp_docs] for more
information.

[hugetlbfs_docs]: https://docs.kernel.org/admin-guide/mm/hugetlbpage.html
[thp_docs]: https://www.kernel.org/doc/html/next/admin-guide/mm/transhuge.html#hugepages-in-tmpfs-shmem
