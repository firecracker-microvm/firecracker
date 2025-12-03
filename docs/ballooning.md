# Using the balloon device with Firecracker

## What is the balloon device

A memory balloon device is a virtio device that can be used to reclaim and give
back guest memory through API commands issued by the host. It does this by
allocating memory in the guest, and then sending the addresses of that memory to
the host; the host may then remove that memory at will. The device is configured
through a number of options, and an integer, which represents the target size of
the balloon, in MiB. The options cannot be changed during operation, but the
target size can be changed.

The behaviour of the balloon is the following: while the actual size of the
balloon (i.e. the memory it has allocated) is smaller than the target size, it
continually tries to allocate new memory -- if it fails, it prints an error
message (`Out of puff! Can't get %d pages`), sleeps for 0.2 seconds, and then
tries again. While the actual size of the balloon is larger than the target
size, it will free memory until it hits the target size.

The device can be configured with the following options:

- `deflate_on_oom`: if this is set to `true` and a guest process wants to
  allocate some memory which would make the guest enter an out-of-memory state,
  the kernel will take some pages from the balloon and give them to said process
  instead asking the OOM killer process to kill some processes to free memory.
  Note that this applies to physical page allocations in the kernel which belong
  to guest processes. This does not apply to instances when the kernel needs
  memory for its activities (i.e. constructing caches), when the user requests
  more memory than the currently available to the balloon for releasing, or when
  guest processes try to allocate large amounts of memory that are refused by
  the guest memory manager, which is possible when the guest runs with
  `vm.overcommit_memory=0` and the allocation does not pass the MM basic checks.
  Setting `vm.memory_overcommit` to 1 would make the MM approve all allocations,
  no matter how large, and using the memory mapped for those allocations will
  always deflate the balloon instead of making the guest enter an OOM state.
  Note: we do not recommend running with `vm.overcommit_memory=1` because it
  requires complete control over what allocations are done in the guest and can
  easily result in unexpected OOM scenarios.
- `stats_polling_interval_s`: unsigned integer value which if set to 0 disables
  the virtio balloon statistics and otherwise represents the interval of time in
  seconds at which the balloon statistics are updated.

The device has two optional features which can be enabled with the following
options:

- `free_page_reporting`: A mechanism for the guest to continually report ranges
  of memory which the guest is not using and can be reclaimed.
  [Read more here](#virtio-balloon-free-page-reporting)
- [(Developer Preview)](../docs/RELEASE_POLICY.md#developer-preview-features)
  `free_page_hinting`: A mechanism to reclaim memory from the guest, this is
  instead triggered from the host.
  [Read more here](#virtio-balloon-free-page-hinting)

## Security disclaimer

**The balloon device is a paravirtualized virtio device that requires
cooperation from a driver in the guest.**

In normal conditions, the balloon device will:

- not change the target size, which is set directly by the host
- consume exactly as many pages as required to achieve the target size
- correctly update the value of the actual size of the balloon seen by the host
- not use pages that were previously inflated if they were not returned to the
  guest via a deflate operation (unless the `deflate_on_oom` flag was set and
  the guest is in an out of memory state)
- provide correct statistics when available

However, Firecracker does not and cannot introspect into the guest to check the
integrity of the balloon driver. As the guest is not trusted, if the driver in
the guest becomes compromised, the above statements are **no longer
guaranteed**.

This means that even though users use the balloon to impose restrictions on
memory usage, they can be broken by a compromised driver in the guest. The
balloon device operates on a best effort model and users should always ensure
the host is prepared to handle a situation in which the Firecracker process uses
all of the memory it was given at boot even if the balloon was used to restrict
the amount of memory available to the guest. It is also the users'
responsibility to monitor the memory consumption of the VM and, in case
unexpected increases in memory usage are observed, we recommend the following
options:

- migrate the VM to a machine with higher memory availability through
  snapshotting at the cost of disrupting the workload;
- kill the Firecracker process that exceeds memory restrictions;
- enable swap with a sufficient amount of memory to handle the demand at the
  cost of memory access speed;

Users should also never rely solely on the statistics provided by the balloon
when controlling the Firecracker process as they are provided directly by the
guest driver and should always be viewed as an indication rather than a
guarantee of what the memory state looks like in the guest.

Please note that even in the case where the driver is not working properly, the
balloon will never leak memory from one Firecracker process to another, nor can
a guest within Firecracker access information in memory outside its own guest
memory. In other words, memory cannot leak in or out of Firecracker if the
driver becomes corrupted. This is guaranteed by the fact that the page frame
numbers coming from the driver are checked to be inside the guest memory, then
`madvise`d with the `MADV_DONTNEED` flag, which breaks the mappings between host
physical memory (where the information is ultimately stored) and Firecracker
virtual memory, which is what Firecracker uses to build the guest memory. On
subsequent accesses on previously `madvise`d memory addresses, the memory is
zeroed. Furthermore, the guest memory is `mmap`ped with the `MAP_PRIVATE` and
`MAP_ANONYMOUS` flags, which ensure that even if a Firecracker yields some
information through an inflate and that same physical page containing the
information is mapped onto another Firecracker process, reads on that address
space will see zeroes.

## Prerequisites

To support memory ballooning, you must use a kernel that has the memory
ballooning driver installed (on Linux 4.14.193, the relevant settings are
`CONFIG_MEMORY_BALLOON=y`, `CONFIG_VIRTIO_BALLOON=y`). Other than that, only the
requirements mentioned in the `getting-started` document are needed.

## Installing the balloon device

In order to use a balloon device, you must install it during virtual machine
setup (i.e. before starting the virtual machine). This can be done either
through a PUT request on "/balloon" or by inserting the balloon into the JSON
configuration file given as a command line argument to the Firecracker process.

Here is an example command on how to install the balloon through the API:

```console
socket_location=...
amount_mib=...
deflate_on_oom=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mib\": $amount_mib, \
        \"deflate_on_oom\": $deflate_on_oom, \
        \"stats_polling_interval_s\": $polling_interval \
    }"
```

To use this, set `socket_location` to the location of the firecracker socket (by
default, at `/run/firecracker.socket`. Then, set `amount_mib`, `deflate_on_oom`
and `stats_polling_interval_s` as desired: `amount_mib` represents the target
size of the balloon, and `deflate_on_oom` and `stats_polling_interval_s`
represent the options mentioned before.

To install the balloon via the JSON config file, insert the following JSON
object into your configuration file:

```console
"balloon": {
    "amount_mib": 0,
    "deflate_on_oom": false,
    "stats_polling_interval_s": 1
},
```

After installing the balloon device, users can poll the configuration of the
device at any time by sending a GET request on "/balloon". Here is an example of
such a request:

```console
socket_location=...

curl --unix-socket $socket_location -i \
    -X GET 'http://localhost/balloon' \
    -H 'Accept: application/json'
```

On success, this request returns a JSON object of the same structure as the one
used to configure the device (via a PUT request on "/balloon").

## Operating the traditional balloon device

After it has been installed, the balloon device can only be operated via the API
through the following command:

```console
socket_location=...
amount_mib=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PATCH 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mib\": $amount_mib, \
        \"stats_polling_interval_s\": $polling_interval \
    }"
```

This will update the target size of the balloon to `amount_mib` and the
statistics polling interval to `polling_interval`.

> [!NOTE] Balloon inflation instructs the guest to reclaim memory which may
> cause performance issues in the guest. The balloon statistics defined
> [below](#virtio-balloon-statistics) can be used to decide whether it's
> necessary to reclaim memory.

## Virtio balloon statistics

The statistics are enabled by setting the `stats_polling_interval_s` field in
the balloon configuration to a non-zero value. If enabled, users can receive the
latest balloon statistics by issuing a GET request on "/balloon". Here is an
example of such a request:

```console
socket_location=...

curl --unix-socket $socket_location -i \
    -X GET 'http://localhost/balloon/statistics' \
    -H 'Accept: application/json'
```

The request, if successful, will return a JSON object containing the latest
statistics. The JSON object contains information about the target and actual
sizes of the balloon as well as virtio traditional memory balloon statistics.

The target and actual sizes of the balloon are expressed as follows:

- `target_pages`: The target size of the balloon, in 4K pages.
- `actual_pages`: The number of 4K pages the device is currently holding.
- `target_mib`: The target size of the balloon, in MiB.
- `actual_mib`: The number of MiB the device is currently holding.

These values are taken directly from the config space of the device and are
always up to date, in the sense that they are exactly what the Firecracker
process reads when polling the config space. The `actual` fields being accurate
are subject to the guest driver working correctly.

As defined in the virtio 1.1 specification, the traditional virtio balloon
device has support for the following statistics:

- `VIRTIO_BALLOON_S_SWAP_IN`: The amount of memory that has been swapped in (in
  bytes).
- `VIRTIO_BALLOON_S_SWAP_OUT`: The amount of memory that has been swapped out to
  disk (in bytes).
- `VIRTIO_BALLOON_S_MAJFLT`: The number of major page faults that have occurred.
- `VIRTIO_BALLOON_S_MINFLT`: The number of minor page faults that have occurred.
- `VIRTIO_BALLOON_S_MEMFREE`: The amount of memory not being used for any
  purpose (in bytes).
- `VIRTIO_BALLOON_S_MEMTOT`: The total amount of memory available (in bytes).
- `VIRTIO_BALLOON_S_AVAIL`: An estimate of how much memory is available (in
  bytes) for starting new applications, without pushing the system to swap.
- `VIRTIO_BALLOON_S_CACHES`: The amount of memory, in bytes, that can be quickly
  reclaimed without additional I/O. Typically these pages are used for caching
  files from disk.
- `VIRTIO_BALLOON_S_HTLB_PGALLOC`: The number of successful hugetlb page
  allocations in the guest.
- `VIRTIO_BALLOON_S_HTLB_PGFAIL`: The number of failed hugetlb page allocations
  in the guest.

Since linux v6.12, following metrics added(omitted in < v6.12):

- `VIRTIO_BALLOON_S_OOM_KILL`: OOM killer invocations, indicating critical
  memory pressure.
- `VIRTIO_BALLOON_S_ALLOC_STALL`: Counter of Allocation enter a slow path to
  gain more memory page. The reclaim/scan metrics can reveal what is actually
  happening.
- `VIRTIO_BALLOON_S_ASYNC_SCAN`: Amount of memory scanned asynchronously.
- `VIRTIO_BALLOON_S_DIRECT_SCAN`: Amount of memory scanned directly.
- `VIRTIO_BALLOON_S_ASYNC_RECLAIM`: Amount of memory reclaimed asynchronously.
- `VIRTIO_BALLOON_S_DIRECT_RECLAIM`: Amount of memory reclaimed directly.

When the pages_high watermark is reached, Linux `kswapd` performs asynchronous
page reclaim, which increases ASYNC_SCAN and ASYNC_RECLAIM.

When a process allocates more memory than the kernel can provide, the process is
stalled while pages are reclaimed directly, which increases DIRECT_SCAN and
DIRECT_RECLAIM.

> `man sar`: %vmeff Calculated as pgsteal(RECLAIM) / pgscan(SCAN), this is a
> metric of the efficiency of page reclaim. If it is near 100% then almost every
> page coming off the tail of the inactive list is being reaped. If it gets too
> low (e.g. less than 30%) then the virtual memory is having some difficulty.

The driver is queried for updated statistics every time the amount of time
specified in that field passes. The driver may not provide all the statistics
when queried, in which case the old values of the missing statistics are
preserved.

To change the statistics polling interval, users can sent a PATCH request on
"/balloon/statistics". Here is an example of such a request:

```console
socket_location=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PATCH 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{ \"stats_polling_interval_s\": $polling_interval }"
```

This will change the statistics polling interval to `polling_interval`. Note
that if the balloon was configured without statistics pre-boot, the statistics
cannot be enabled later by providing a `polling_interval` non-zero value.
Furthermore, if the balloon was configured with statistics pre-boot through a
non-zero `stats_polling_interval_s` value, the statistics cannot be disabled
through a `polling_interval` value of zero post-boot.

## Virtio balloon free page reporting

Free page reporting is a virtio balloon feature which allows the guest OS to
report ranges of memory which are not being used. In Firecracker, the balloon
device will `madvise` the range with the `MADV_DONTNEED` flag, reducing the RSS
of the guest. Reporting can only be enabled pre-boot and will run continually
with no option to stop it running. The feature also requires the guest to have
the Linux kernel config option `PAGE_REPORTING` enabled.

To enable free page reporting when creating the balloon device, the
`free_page_reporting` attribute should be set in the JSON object.

An example of how to configure the device to enable free page reporting:

```console
socket_location=...
amount_mib=...
deflate_on_oom=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mib\": $amount_mib, \
        \"deflate_on_oom\": $deflate_on_oom, \
        \"stats_polling_interval_s\": $polling_interval, \
        \"free_page_reporting\": true \
    }"
```

The Linux driver uses a hook in the free page path to trigger the reporting
process, which will begin after a short delay (~2 seconds) and report the
ranges. The runtime impact of this feature is heavily workload dependent. The
driver gets ranges from the buddy allocator with a minimum page order. This page
order dictates the minimum size of ranges reported and can be configured with
the `page_reporting_order` module parameter in the guest kernel. The page order
comes with trade-offs between performance and memory reclaimed; a good target to
maximise memory reclaim is to have the reported ranges match the backing page
size.

## Virtio balloon free page hinting

Free page hinting is a
[developer-preview](../docs/RELEASE_POLICY.md#developer-preview-features)
feature, which allows the guest driver to report ranges of memory which are not
being used. In Firecracker, the balloon device will `madvise` the range with the
`MADV_DONTNEED` flag, reducing the RSS of the guest. Free page hinting differs
from reporting as this is instead initiated from the host side, giving more
flexibility on when to reclaim memory.

To enable free page hinting when creating the balloon device, the
`free_page_hinting` attribute should be set in the JSON object.

An example of how to configure the device to enable free page hinting:

```console
socket_location=...
amount_mib=...
deflate_on_oom=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mib\": $amount_mib, \
        \"deflate_on_oom\": $deflate_on_oom, \
        \"stats_polling_interval_s\": $polling_interval, \
        \"free_page_hinting\": true \
    }"
```

Free page hinting is initiated and managed by Firecracker, the core mechanism to
control the run is with the `cmd_id`. When Firecracker sets the `cmd_id` to a
new number, the driver will acknowledge this and start reporting ranges, which
Firecracker will free. Once the device has reported all the ranges it can find,
it will update the `cmd_id` to reflect this. The device will then hold these
ranges until Firecracker sends the stop command which allows the guest driver to
reclaim the memory. The time required for the guest to complete a hinting run is
dependant on a multitude of different factors and is mostly dictated by the
guest, however, in testing the average time is ~200 milliseconds for a 1GB VM.

This control mechanism in Firecracker is managed through three separate
endpoints `/balloon/hinting/start`, `/balloon/hinting/status` and
`/balloon/hinting/stop`. For simple operation, call the start endpoint with
`acknowledge_on_stop = true`, which will automatically send the stop command
once the driver has finished.

An example of sending this command:

```console
curl --unix-socket $socket_location -i \
    -X POST 'http://localhost/balloon/hinting/start' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"acknowledge_on_stop\": true \
    }"
```

For fine-grained control, using `acknowledge_on_stop = false`, Firecracker will
not send the acknowledge message. This can be used to get the guest to hold onto
more memory. Using the `/status` endpoint, you can get information about the
last `cmd_id` sent by Firecracker and the last update from the guest.

An example of the status request and response:

```console
curl --unix-socket $socket_location -i \
    -X GET 'http://localhost/balloon/hinting/status' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json'
```

Response:

```json
{
  "host_cmd": 1,
  "guest_cmd": 2
}
```

An example of the stop endpoint:

```console
curl --unix-socket $socket_location -i \
    -X POST 'http://localhost/balloon/hinting/stop' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{}"
```

On snapshot restore, the `cmd_id` is **always** set to the stop `cmd_id` to
allow the guest to reclaim the memory. If you have a particular use-case which
requires this not to be the case, please raise an issue with a description of
your scenario.

> [!WARNING]
>
> Free page hinting was primarily designed for live migration, because of this
> there is a caveat to the device spec which means the guest is able to reclaim
> memory before Firecracker even receives the range to free. This can lead to a
> scenario where the device frees memory that has been reclaimed in the guest,
> potentially corrupting memory. The chances of this race happening are low, but
> not impossible; hence the developer-preview status.
>
> We are currently working with the kernel community on a feature that will
> eliminate this race. Once this has been resolved, we will update the device.
>
> One way to safely use this feature when using UFFD is:
>
> 1. Enable `WRITEPROTECT` on the VM memory before starting a hinting run.
> 1. Track ranges that are written to.
> 1. Skip these ranges when Firecracker reports them for freeing.
>
> This will prevent ranges which have been reclaimed from being freed.

## Balloon Caveats

- Firecracker has no control over the speed of inflation or deflation; this is
  dictated by the guest kernel driver.

- The traditional balloon will continually attempt to reach its target size,
  which can be a CPU-intensive process. It is therefore recommended to set
  realistic targets or, after a period of stagnation in the inflation, update
  the target size to be close to the inflated size.

- The `deflate_on_oom` flag is a mechanism to prevent the guest from crashing or
  terminating processes; it is not meant to be used continually to free memory.
  Doing this will be a CPU-intensive process, as the traditional balloon driver
  is designed to deflate and release memory slowly. This is also compounded if
  the balloon has yet to reach its target size, as it will attempt to inflate
  while also deflating.
