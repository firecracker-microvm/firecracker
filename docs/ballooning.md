# Using the balloon device with Firecracker

## What is the balloon device

A memory balloon device is a virtio device that can be used to reclaim and
give back guest memory through API commands issued by the host. It does this
by allocating memory in the guest, and then sending the
addresses of that memory to the host; the host may then remove that memory at
will. The device is configured through a number of options, and an integer,
which represents the target size of the balloon, in MiB. The options cannot be
changed during operation, but the target size can be changed.

The behaviour of the balloon is the following: while the actual size of the
balloon (i.e. the memory it has allocated) is smaller than the target size,
it continually tries to allocate new memory -- if it fails, it prints an
error message (`Out of puff! Can't get %d pages`), sleeps for 0.2 seconds, and
then tries again. While the actual size of the balloon is larger than the
target size, it will free memory until it hits the target size.

The device can be configured with the following options:
* `deflate_on_oom`: if this is set to `true` and a guest process wants to
allocate some memory which would make the guest enter an out-of-memory state,
the kernel will take some pages from the balloon and give them to said
process instead asking the OOM killer process to kill some processes to free
memory. Note that this applies to allocations from guest processes which would
make the system enter an OOM state. This does not apply to instances when the
kernel needs memory for its activities (i.e. constructing caches), or when the
user requests more memory than the amount available through an inflate.
* `must_tell_host`: if this is set to `true`, the kernel will wait for host
confirmation before reclaiming memory from the host. This option is not useful
in Firecracker's implementation of the balloon device because Firecracker does
not perform any additional operations on returned pages, so it makes no
difference if the guest waits for the host's approval on returned pages or not.
Therefore, this option can be safely set to `false`.
* `stats_polling_interval_s`: unsigned integer value which if set to 0
disables the virtio balloon statistics and otherwise represents the interval
of time in seconds at which the balloon statistics are updated.

## Security disclaimer

> [!IMPORTANT]
> The balloon device is a paravirtualized virtio device that requires cooperation
from a driver in the guest.

In normal conditions, the balloon device will:
* not change the target size, which is set directly by the host
* consume exactly as many pages as required to achieve the target size
* correctly update the value of the actual size of the balloon seen by the host
* not use pages that were previously inflated if they were not returned to the
guest via a deflate operation (unless the `deflate_on_oom` flag was set and the
guest is in an out of memory state)
* provide correct statistics when available

However, Firecracker does not and cannot introspect into the guest to check the
integrity of the balloon driver. As the guest is not trusted, if the driver in
the guest becomes compromised, the above statements are
**no longer guaranteed**.

This means that even though users use the balloon to impose restrictions on
memory usage, they can be broken by a compromised driver in the guest. The
balloon device operates on a best effort model and users should always ensure
the host is prepared to handle a situation in which the Firecracker process
uses all of the memory it was given at boot even if the balloon was used to
restrict the amount of memory available to the guest.

Users should also never rely solely on the statistics provided by the balloon
when controlling the Firecracker process as they are provided directly by the
guest driver.

Please note that even in the case where the driver is not working properly,
the balloon will never leak memory from one Firecracker process to another,
nor can a guest within Firecracker access information in memory outside its
own guest memory. In other words, memory cannot leak in or out of Firecracker
if the driver becomes corrupted. This is guaranteed by the fact that the page
frame numbers coming from the driver are checked to be inside the guest
memory, then `madvise`d with the `MADV_DONTNEED` flag, which breaks the
mappings between host physical memory (where the information is ultimately
stored) and Firecracker virtual memory, which is what Firecracker uses to
build the guest memory. On subsequent accesses on previously `madvise`d
memory addresses, the memory is zeroed. Furthermore, the guest memory is
`mmap`ped with the `MAP_PRIVATE` and `MAP_ANONYMOUS` flags, which ensure that
even if a Firecracker yields some information through an inflate and that
same physical page containing the information is mapped onto another
Firecracker process, reads on that address space will see zeroes.

## Prerequisites

To support memory ballooning, you must use a kernel that has the memory
ballooning driver installed (on Linux 4.14.193, the relevant settings are
`CONFIG_MEMORY_BALLOON=y`, `CONFIG_VIRTIO_BALLOON=y`). Other than that, only
the requirements mentioned in the `getting-started` document are needed.

## Installing the balloon device

In order to use a balloon device, you must install it during virtual machine
setup (i.e. before starting the virtual machine). This can be done either
through a PUT request on "/balloon" or by inserting the balloon into the JSON
configuration file given as a command line argument to the Firecracker process.

Here is an example command on how to install the balloon through the API:

```
socket_location=...
amount_mb=...
must_tell_host=...
deflate_on_oom=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mb\": $amount_mb, \
        \"must_tell_host\": $must_tell_host, \
        \"deflate_on_oom\": $deflate_on_oom, \
        \"stats_polling_interval_s\": $polling_interval \
    }"
```

To use this, set `socket_location` to the location of the firecracker socket
(by default, at `/run/firecracker.socket`. Then, set `amount_mb`,
`must_tell_host`, `deflate_on_oom` and `stats_polling_interval_s` as
desired: `num_pages` represents the target size of the balloon, and
`must_tell_host`, `deflate_on_oom` and `stats_polling_interval_s`
represent the options mentioned before.

To install the balloon via the JSON config file, insert the following JSON
object into your configuration file:

```
"balloon": {
    "amount_mb": 0,
    "must_tell_host": false,
    "deflate_on_oom": false,
    "stats_polling_interval_s": 1
},
```

After installing the balloon device, users can poll the configuration of the
device at any time by sending a GET request on "/balloon". Here is an example
of such a request:

```
socket_location=...

curl --unix-socket $socket_location -i \
    -X GET 'http://localhost/balloon' \
    -H 'Accept: application/json'
```

On success, this request returns a JSON object of the same structure as the
one used to configure the device (via a PUT request on "/balloon").

## Operating the balloon device

After it has been installed, the balloon device can only be operated via the
API through the following command:

```
socket_location=...
amount_mb=...
polling_interval=...

curl --unix-socket $socket_location -i \
    -X PATCH 'http://localhost/balloon' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"amount_mb\": $amount_mb, \
        \"stats_polling_interval_s\": $polling_interval \
    }"
```

This will update the target size of the balloon to `amount_mb` and the
statistics polling interval to `polling_interval`.

## Virtio balloon statistics

The statistics are enabled by setting the `stats_polling_interval_s` field
in the balloon configuration to a non-zero value. If enabled, users can receive
the latest balloon statistics by issuing a GET request on "/balloon". Here is
an example of such a request:

```
socket_location=...

curl --unix-socket $socket_location -i \
    -X GET 'http://localhost/balloon/statistics' \
    -H 'Accept: application/json'
```

The request, if successful, will return a JSON object containing the latest
statistics. The JSON object contains information about the target and actual
sizes of the balloon as well as virtio traditional memory balloon statistics.

The target and actual sizes of the balloon are expressed as follows:

* `target_pages`: The target size of the balloon, in 4K pages.
* `actual_pages`: The number of 4K pages the device is currently holding.
* `target_mb`: The target size of the balloon, in MiB.
* `actual_mb`: The number of MiB the device is currently holding.

These values are taken directly from the config space of the device and are
always up to date, in the sense that they are exactly what the Firecracker
process reads when polling the config space. The `actual` fields being
accurate are subject to the guest driver working correctly.

As defined in the virtio 1.1 specification, the traditional virtio balloon
device has support for the following statistics:

* `VIRTIO_BALLOON_S_SWAP_IN`: The amount of memory that has been swapped in
(in bytes). 
* `VIRTIO_BALLOON_S_SWAP_OUT`: The amount of memory that has been swapped out
to disk (in bytes). 
* `VIRTIO_BALLOON_S_MAJFLT`: The number of major page faults that have
occurred. 
* `VIRTIO_BALLOON_S_MINFLT`: The number of minor page faults that have
occurred. 
* `VIRTIO_BALLOON_S_MEMFREE`: The amount of memory not being used for any
purpose (in bytes). 
* `VIRTIO_BALLOON_S_MEMTOT`: The total amount of memory available (in bytes). 
* `VIRTIO_BALLOON_S_AVAIL`: An estimate of how much memory is available (in
bytes) for starting new applications, without pushing the system to swap. 
* `VIRTIO_BALLOON_S_CACHES`: The amount of memory, in bytes, that can be
quickly reclaimed without additional I/O. Typically these pages are used for
caching files from disk. 
* `VIRTIO_BALLOON_S_HTLB_PGALLOC`: The number of successful hugetlb page
allocations in the guest. 
* `VIRTIO_BALLOON_S_HTLB_PGFAIL`: The number of failed hugetlb page allocations
in the guest.

The driver is querried for updated statistics every time the amount
of time specified in that field passes. The driver may not provide all the
statistics when querried, in which case the old values of the missing
statistics are preserved.

To change the statistics polling interval, users can sent a PATCH request
on "/balloon/statistics". Here is an example of such a request:

```
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
non-zero `stats_polling_interval_s` value, the statistics cannot be
disabled through a `polling_interval` value of zero post-boot.