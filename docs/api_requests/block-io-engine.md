# Block device IO engine

For all Firecracker versions prior to v1.0.0, the emulated block device uses a
synchronous IO engine for executing the device requests, based on blocking
system calls.

Firecracker 1.0.0 adds support for an asynchronous block device IO engine.

> [!WARNING]
>
> Support is currently in **developer preview**. See
> [this section](#developer-preview-status) for more info.

The `Async` engine leverages [`io_uring`](https://kernel.dk/io_uring.pdf) for
executing requests in an async manner, therefore getting overall higher
throughput by taking better advantage of the block device hardware, which
typically supports queue depths greater than 1.

The block IO engine is configured via the PUT /drives API call (pre-boot only),
with the `io_engine` field taking two possible values:

- `Sync` (default)
- `Async` (in [developer preview](../RELEASE_POLICY.md))

The `Sync` variant is the default, in order to provide backwards compatibility
with older Firecracker versions.

**Note** [vhost-user block device](./block-vhost-user.md) is another option for
block IO that requires an external backend process.

## Example configuration

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/rootfs" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"rootfs\",
             \"path_on_host\": \"${drive_path}\",
             \"is_root_device\": true,
             \"is_read_only\": false,
             \"io_engine\": \"Sync\"
         }"
```

## Host requirements

Firecracker requires a minimum host kernel version of 5.10.51 for the `Async` IO
engine.

This requirement is based on the availability of the `io_uring` subsystem, as
well as a couple of features and bugfixes that were added in newer kernel
versions.

If a block device is configured with the `Async` io_engine on a host kernel
older than 5.10.51, the API call will return a 400 Bad Request, with a
suggestive error message.

## Performance considerations

The performance is strictly tied to the host kernel version. The gathered data
may not be relevant for modified/newer kernels than 5.10.

### Device creation

When using the `Async` variant, there is added latency on device creation (up to
~110 ms), caused by the extra io_uring system calls performed by Firecracker.
This translates to higher latencies on either of these operations:

- API call duration for block device config
- Boot time for VMs started via JSON config files
- Snapshot restore time

For use-cases where the lowest latency on the aforementioned operations is
desired, it is recommended to use the `Sync` IO engine.

### Block IOPS and efficiency

The `Async` engine performance potential is showcased when the block device
backing files are placed on a physical disk that supports efficient parallel
execution of requests, like an NVME drive. It's also recommended to evenly
distribute the backing files across the available drives of a host, to limit
contention in high-density scenarios.

The performance measurements we've done were made on NVME drives, and we've
discovered that:

For __read__ workloads which operate on data that is not present in the host
page cache, the performance improvement for `Async` is about 1.5x-3x in overall
efficiency (IOPS per CPU load) and up to 30x in total IOPS.

For __write__ workloads, the `Async` engine brings an improvement of about
20-45% in total IOPS but performs worse than the `Sync` engine in total
efficiency (IOPS per CPU load). This means that while Firecracker will achieve
better performance, it will be at the cost of consuming more CPU for the kernel
workers. In this case, the VMM cpu load is also reduced, which should translate
into performance increase in hybrid workloads (block+net+vsock).

Whether or not using the `Async` engine is a good idea performance-wise depends
on the workloads and the amount of spare CPU available on a host. According to
our NVME experiments, io_uring will always bring performance improvements
(granted that there are enough available CPU resources).

It is recommended that users perform some tests with examples of expected
workloads and measure the efficiency as (IOPS/CPU load).

## Developer preview status

View the [release policy](../RELEASE_POLICY.md) for information about developer
preview terminology.

The `Async` io_engine is not yet suitable for production use. It will be made
available for production once Firecracker has support for a host kernel that
implements mitigation mechanisms for the following threats:

### Threat 1: PID exhaustion

The number of io_uring kernel workers assigned to one Firecracker block device
is upper-bounded by:

```
(1 + NUMA_COUNT * min(size_of_ring, 4 * NUMBER_OF_CPUS)
```

This formula is derived from the 5.10 linux kernel code, while `size_of_ring` is
hardcoded to `128` in Firecracker.

Depending on the number of microVMs that can concurrently live on a host and the
number of block devices configured for each microVM, the kernel PID limit may be
reached, resulting in failure to create any new process.

Kernels starting with 5.15 expose a configuration option for customising this
upper bound. Once possible, we plan on exposing this in the Firecracker drive
configuration interface.

### Threat 2: worker thread resource consumption

The io_uring kernel workers are spawned in the root cgroup of the system. They
don’t inherit the Firecracker cgroup, cannot be moved out of the root cgroup and
their names don't contain any information about the microVM's PID. This makes it
impossible to attribute a worker to a specific Firecracker VM and limit the CPU
and memory consumption of said workers via cgroups.

Starting with kernel 5.12 (currently unsupported), the Firecracker cgroup is
inherited by the io_uring workers.

### Path to GA

We plan on marking the Async engine as production ready once an LTS linux kernel
including mitigations for the aforementioned mitigations is released and support
for it is added in Firecracker.

Read more about Firecracker's [kernel support policy](../kernel-policy.md).
