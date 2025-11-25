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
microVMs backed with huge pages can only be restored via UFFD.

When restoring snapshots via UFFD, Firecracker will send the configured page
size (in KiB) for each memory region as part of the initial handshake, as
described in our documentation on
[UFFD-assisted snapshot-restore](snapshotting/handling-page-faults-on-snapshot-resume.md).

## Transparent huge pages (THP)

Firecracker supports enabling transparent huge pages on guest memory via the
`enable_thp` field under `/machine-config`. When `enable_thp` is set to `true`,
Firecracker uses `madvise(MADV_HUGEPAGE)` to request THP for the guest memory
regions it allocates.

Limitations:
- THP is only attempted for explicit hugetlbfs pages (i.e., `huge_pages` is
  `None`).
- THP is not supported for memfd-backed guest memory (e.g., when using
  vhost-user-blk); in this case Firecracker will return an error if
  `enable_thp` is set.
- THP does not integrate with UFFD; no transparent huge pages will be
  allocated during userfault-handling while resuming from a snapshot.

Please refer to the [Linux Documentation][thp_docs] for more information.

## Known Limitations

Currently, hugetlbfs support is mutually exclusive with the following
Firecracker features:

- Memory Ballooning via the [Balloon Device](./ballooning.md)

Furthermore, enabling dirty page tracking for hugepage memory negates the
performance benefits of using huge pages. This is because KVM will
unconditionally establish guest page tables at 4K granularity if dirty page
tracking is enabled, even if the host users huge mappings.

[hugetlbfs_docs]: https://docs.kernel.org/admin-guide/mm/hugetlbpage.html
[thp_docs]: https://www.kernel.org/doc/html/next/admin-guide/mm/transhuge.html#hugepages-in-tmpfs-shmem
