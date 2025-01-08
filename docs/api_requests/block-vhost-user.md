# Vhost-user block device

> [!WARNING]
>
> Support is currently in **developer preview**. See
> [this section](../RELEASE_POLICY.md#developer-preview-features) for more info.

As an alternative to [file-backed block device](block-io-engine.md) `Sync` and
`Async` engines, Firecracker supports a vhost-user block device.

There is a good introduction of how a vhost-user block device works in general
at
[FOSDEM23](https://archive.fosdem.org/2023/schedule/event/sds_vhost_user_blk).

[Vhost-user](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html) is a
userspace protocol that allows to delegate Virtio queue processing to another
userspace process on the host, as opposed to performing this task within
Firecracker's VMM thread.

In the vhost-user architecture, the VMM acts as a vhost-user frontend and it is
responsible for:

- connecting to the backend via a Unix domain socket (UDS)
- feature negotiation with the backend and the guest
- handling device configuration requests from the guest
- sharing sufficient information about the guest memory and Virtio queues with
  the backend

The vhost-user backend receives the information from the frontend and performs
handling of IO requests from the guest.

The UDS socket is only used for control plane purposes and does not participate
in the data plane.

Firecracker only implements a vhost-user frontend. Users are free to choose from
[existing open source backends](#backends) or implement their own.

## Topology

Each vhost-user device connects to its own UDS socket. There is no way for
multiple devices to share a single socket, as there is no way to differentiate
messages related to devices at the vhost-user protocol level.

Each device can be served by a separate backend or a single backend can serve
multiple devices.

## Interactions with the backend

There are three points when the vhost-user frontend communicates with the
backend:

1. Device initialisation. When a vhost-user device is created, Firecracker
   connects to the corresponding UDS socket and negotiates Virtio and Vhost
   features with backend and retrieves device configuration.
1. Device activation. When the guest driver finishes setting up the device,
   Firecracker shares memory tables and Virtio queue information with the
   backend. As a part of this, Firecracker shares file descriptors for guest's
   memory regions, as well as file descriptors for queue notifications.
1. Config update. When receving a
   [`PATCH` request](./patch-block.md#updating-vhost-user-block-devices-after-boot)
   on a vhost-user backed drive, Firecracker rerequests the device config from
   the backend in order to make the new config available to the guest.

## Advantages

While vhost-user block is considered an optimisation to Firecracker IO, a naive
implementation of the backend is not going to improve performance.

The major advantage of using a vhost-user device is that the backend can
implement custom processing logic. It can use intelligent algorithms to serve
block requests, eg by fetching the block device data over the network or using
sophisticated readahead logic. In such cases, the performance improvement will
be coming from the fact that the custom logic is implemented in the same process
that handles Virtio queues, which reduces the number of required context
switches.

## Disadvantages

In order for the backend to be able to process virtio requests, guest memory
needs to be shared by the frontend to the backend. This means, a shared memory
mapping is required to back guest memory. When a vhost-user device is
configured, Firecracker uses `memfd_create` instead of creating an anonymous
private mapping to achieve that. It was observed that page faults to a shared
memory mapping take significantly longer (up to 24% in our testing), because
Linux memory subsystem has to use atomic memory operations to update page
status, which is an expensive operation under specific conditions. We advise
users to profile performance on their workloads when considering to use
vhost-user devices.

## Other considerations

Compared to virtio block device where Firecracker interacts with a drive file on
the host, vhost-user block device is handled by the backend directly. Some
workloads may benefit from caching and readahead that the host pagecache offers
for the backing file. This benefit is not available in vhost-user block case.
Users may need to implement internal caching within the backend if they find it
appropriate.

## Backends

There are a number of open source implementations of a vhost-user backend
available for reference that can help developing a custom backend:

1. [Qemu backend](https://github.com/qemu/qemu/tree/master/contrib/vhost-user-blk)
1. [Cloud Hypervisor backend](https://github.com/cloud-hypervisor/cloud-hypervisor/tree/main/vhost_user_block)
1. [crosvm backend](https://github.com/google/crosvm/blob/main/devices/src/virtio/vhost/user/device/block.rs)
1. [SPDK backend](https://github.com/spdk/spdk/blob/master/lib/vhost/vhost_blk.c)

## Security considerations

### Guest memory sharing

By design, a vhost-user frontend must share file descriptors of all guest memory
regions to the backend. In order to achive that, guest memory is created as a
[memfd](https://man7.org/linux/man-pages/man2/memfd_create.2.html) and mapped as
`MAP_SHARED`.

#### File descriptor in procfs

An open `memfd` is reflected in `procfs` as any other open file descriptor:

```shell
$ ls -l /proc/{pid}/fd | grep memfd
lrwx------ 1 1234 1234 64 Nov  2 13:39 32 -> /memfd:guest_mem (deleted)
```

Any process on the host that has access to this file in `procfs` will be able to
map the file descriptor and observe runtime behaviour of the guest.

At the moment, Firecracker does not close the `memfd`, because it must remain
open until all the configured vhost-user devices have been activated and their
info shared with the backends. This kind of tracking is not implemented in
Firecracker, but may be implemented in the future. Meanwhile, users need to make
sure that the access to the Firecracker's `procfs` tree is restricted to trusted
processes on the host.

On the backend side, it is advised that the backend closes the guest memory
region file descriptors after mapping them into its own address space.

#### Resource limit in jailer

The Firecracker [jailer](../jailer.md) allows to configure resource limits for
the Firecracker process. Specifically, it allows to set the maximum file size.
Since `memfd` that is used to back the guest memory is considered a file, the
file size resource limit cannot be less than the biggest guest memory region.
This does not require any special action from a user, but needs to be taken into
consideration.

### Remote code execution in the backend

It is recommended to run Firecracker using the [jailer](../jailer.md). Since the
vhost-user backend interacts with the guest via a Virtio queue, there is a
potential for the guest to exercise issues in the backend codebase to trigger
undesired behaviours. Users should consider running their backend in a jailer or
applying other adequate security measures to restrict it.

**Note** [Firecracker jailer](../jailer.md) is currently only capable of running
Firecracker as the binary. Vhost-user block device users are expected to use
another jailer to run the backend.

It is also recommended to use proactive security measures like running a
Virtio-level fuzzer in the guest during testing to make sure that the backend
correctly handles all possible classes of inputs (including invalid ones) from
the guest.

### Rate limiting / cgroups

Virtio block device in Firecracker has a
[rate limiting capability](../design.md#io-storage-networking-and-rate-limiting).

In the vhost-user case, Firecracker does not participate in handling requests
from the guest, so rate limiting becomes backend's responsibility.

As an additional indirect measure, users can make use of `cgroups` settings
(either via Firecracker jailer or independently) in order to restrict host CPU
consumption of the guest, which would transitively limit guest's IO activity.

### Protection against defects in the backend code

Due to potential defects in the backend (eg mislocating Virtio queues or writes
to a wrong location in the guest memory), the guest execution may be affected.
It is advised that customers monitor guest's health periodically.

Additionally, in order to avoid orhpaned Firecracker processes if the backend
crashes, the backend may need to send a signal, such as `SIGBUS`, to the
Firecracker process for it to exit as well.

### Backend timeouts

In order to correctly handle the case where the Firecracker process exits before
it exchanges all the expected data with the backend, the backend may need to
implement a timeout for how long it waits for Firecracker to connect and/or to
exchange the data via the vhost-user protocol and exit to avoid resource
exhaustion.

## Snapshot support

At the moment, [snapshotting](../snapshotting) is not supported for microVMs
that have vhost-user devices configured. An attempt to take a snapshot of such a
microVM will fail. It is planned to add support for that in the future.

## Example configuration

Run a vhost-user backend, eg Qemu backend:

```bash
vhost-user-blk --socket-path=${backend_socket} --blk-file=${drive_path}
```

Firecracker API request to add a vhost-user block device:

```bash
curl --unix-socket ${fc_socket} -i \
     -X PUT "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
             \"drive_id\": \"scratch\",
             \"socket\": \"${backend_socket}\",
             \"is_root_device\": false
         }"
```

**Note** Unlike Virtio block device, there is no way to configure a `readonly`
vhost-user drive on the Firecracker side. Instead, this configuration belongs to
the backend. Whenever the backend advertises the `VIRTIO_BLK_F_RO` feature,
Firecracker will accept it, and the device will act as readonly.

**Note** Whenever a `PUT` request is sent to the `/drives` endpoint for a
vhost-user device with the `id` that already exists, Firecracker will close the
existing connection to the backend and will open a new one. Users may need to
restart their backend if they do so.
