# Block device caching strategies

Firecracker offers the possiblity of choosing the block device caching strategy.
Caching strategy affects the path data written from inside the microVM takes to
the host persistent storage.

## How it works

When installing a block device through a PUT /drives API call, users can choose
the caching strategy by inserting a `cache_type` field in the JSON body of the
request. The available cache types are:

- `Unsafe`
- `Writeback`

### Unsafe mode (default)

When configuring the block caching strategy to `Unsafe`, the device will not
advertise the VirtIO `flush` feature to the guest driver.

### Writeback mode

When configuring the block caching strategy to `Writeback`, the device will
advertise the VirtIO `flush` feature to the guest driver. If negotiated when
activating the device, the guest driver will be able to send flush requests to
the device. When the device executes a flush request, it will perform an `fsync`
syscall on the backing block file, committing all data in the host page cache to
disk.

## Supported use cases

The caching strategy should be used in order to make a trade-off:

- `Unsafe`
  - enhances performance as fewer syscalls and IO operations are performed when
    running workloads
  - sacrifices data integrity in situations where the host simply loses the
    contents of the page cache without committing them to the backing storage
    (such as a power outage)
  - recommended for use cases with ephemeral storage, such as serverless
    environments
- `Writeback`
  - ensures that once a flush request was acknowledged by the host, the data is
    committed to the backing storage
  - sacrifices performance, from boot time increases to greater
    emulation-related latencies when running workloads
  - recommended for use cases with low power environments, such as embedded
    environments

## How to configure it

Example sequence that configures a block device with a caching strategy:

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/dummy" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"dummy\",
             \"path_on_host\": \"${drive_path}\",
             \"is_root_device\": false,
             \"is_read_only\": false,
             \"cache_type\": \"Writeback\"
         }"
```
