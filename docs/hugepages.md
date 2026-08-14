# Backing Guest Memory by Huge Pages

Firecracker supports three modes for the `huge_pages` field of `PUT` or `PATCH`
requests to the `/machine-config` endpoint:

- `None` (default): Uses the host's default page size (typically 4K) with no
  huge page behavior.
- `Transparent`: Uses `madvise(MADV_HUGEPAGE)` to request transparent huge pages
  for guest memory. Guest memory size must be a multiple of 2MB.
- `2M`: Backs guest memory by 2MB hugetlbfs pages.

## Transparent Huge Pages (THP)

Setting `huge_pages` to `Transparent` enables transparent huge pages for guest
memory via `madvise(MADV_HUGEPAGE)`. This allows the kernel to opportunistically
back guest memory with huge pages without requiring a pre-allocated hugetlbfs
pool.

Note that while traditional THP uses PMD-sized pages (2MB on x86_64), the actual
THP size depends on the CPU architecture. Modern kernels also support
"multi-size THP" (mTHP), which can allocate pages in various power-of-2 sizes
between the base page size and PMD size (e.g. 16K, 32K, 64K). Firecracker
requires guest memory size to be a multiple of 2MB regardless of the THP size
used by the host kernel.

Limitations:

- When vhost-user-blk devices are in use, guest memory is memfd-backed (shared
  memory). THP for shared/shmem memory is controlled separately from anonymous
  memory via `/sys/kernel/mm/transparent_hugepage/shmem_enabled` and may not be
  enabled by default. Refer to the
  [Linux Documentation on shmem THP][thp_shmem_docs] for details on how to
  configure it.
- THP does not integrate with UFFD; no transparent huge pages will be allocated
  during userfault-handling while resuming from a snapshot.

Please refer to the [Linux Documentation][thp_docs] for more information.

## Hugetlbfs (2M)

Setting `huge_pages` to `2M` backs guest memory by 2MB hugetlbfs pages. This can
bring performance improvements for specific workloads, due to less TLB
contention and less overhead during virtual->physical address resolution. It can
also help reduce the number of KVM_EXITS required to rebuild extended page
tables post snapshot restore, as well as improve boot times (by up to 50% as
measured by Firecracker's
[boot time performance tests](../tests/integration_tests/performance/test_boottime.py))

Using hugetlbfs requires the host running Firecracker to have a pre-allocated
pool of 2M pages. Should this pool be too small, Firecracker may behave
erratically or receive the `SIGBUS` signal. This is because Firecracker uses the
`MAP_NORESERVE` flag when mapping guest memory. This flag means the kernel will
not try to reserve sufficient hugetlbfs pages at the time of the `mmap` call,
trying to claim them from the pool on-demand. For details on how to manage this
pool, please refer to the [Linux Documentation][hugetlbfs_docs].

### Huge Pages and Snapshotting

Restoring a Firecracker snapshot of a microVM backed by huge pages will also use
huge pages to back the restored guest. There is no option to flip between
regular, 4K, pages and huge pages at restore time. Furthermore, snapshots of
microVMs backed with huge pages can only be restored via UFFD.

When restoring snapshots via UFFD, Firecracker will send the configured page
size (in KiB) for each memory region as part of the initial handshake, as
described in our documentation on
[UFFD-assisted snapshot-restore](snapshotting/handling-page-faults-on-snapshot-resume.md).

## Known Limitations

Enabling dirty page tracking for hugepage memory negates the performance
benefits of using huge pages. This is because KVM will unconditionally establish
guest page tables at 4K granularity if dirty page tracking is enabled, even if
the host uses huge mappings.

The traditional balloon device reports free pages at 4k granularity, this means
the device is unable to reclaim the hugepage backing of the guest and drop RSS.
However, the balloon can still be inflated and used to restrict memory usage in
the guest.

[hugetlbfs_docs]: https://docs.kernel.org/admin-guide/mm/hugetlbpage.html
[thp_docs]: https://www.kernel.org/doc/html/next/admin-guide/mm/transhuge.html#hugepages-in-tmpfs-shmem
[thp_shmem_docs]: https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html#shmem-internal-tmpfs
