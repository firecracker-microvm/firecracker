# Block device IO engine

For all Firecracker versions prior to v1.0.0, the emulated block device uses a
synchronous IO engine for executing the device requests, based on blocking
system calls.

Firecracker 1.0.0 adds support for a new asynchronous block device IO engine.

The `Async` engine leverages [`io_uring`](https://kernel.dk/io_uring.pdf) for
executing requests in an async manner, therefore getting overall higher
throughput by taking better advantage of the block device hardware, which
typically supports queue depths greater than 1.

The block IO engine is configured via the PUT /drives API call (pre-boot only),
with the `io_engine` field taking two possible values:
- `Sync` (default)
- `Async`

The `Sync` variant is the default, in order to provide backwards compatibility
with older Firecracker versions.

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
             \"io_engine\": \"Async\"
         }"
```

## Host requirements

Firecracker requires a minimum host kernel version of 5.10.0 for the `Async` IO
engine.

This requirement is based on the availability of the `io_uring` subsystem, as
well as a couple of features and bugfixes that were added in newer kernel
versions.

If a block device is configured with the `Async` io_engine on a host kernel
older than 5.10.51, the API call will return a 400 Bad Request, with a
suggestive error message.

## Recommendations

In order to get the higher disk IO throughput, it is recommended to use the
`Async` io_engine on hosts that support it.

When using the `Async` variant, there is added latency on device creation (up
to ~110 ms), caused by the extra io_uring system calls performed by
Firecracker.
This translates to higher latencies on either of these operations:

- API call duration for block device config
- Boot time for VMs started via JSON config files
- Snapshot restore time

For use-cases where the lowest latency on the aforementioned operations is
desired, it is recommended to use the `Sync` IO engine.
