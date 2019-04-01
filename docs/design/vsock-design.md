# Firecracker vsock Design

## Scope

This document aims to describe a socket-based, guest ↔ host, communication
mechanism, provided by the Firecracker VMM. Three main goals are defined for
this mechanism:

- It should maintain the Firecracker security barrier, isolating the guest from
  direct access to any host resources; and
- It should support multiple communication channels; and
- It should be more lightweight than traditional network sockets, in the sense
  of requiring fewer host resources. See
  [this considered approach](#ethernet-host-to-ethernet-guest).

## Context

An established approach to guest ↔ host communication is provided by the VirtIO
vsock device. In its current Linux implementation, this approach requires three
actors: the virtio-vsock driver (provided by the guest OS), the virtio-vosck
device control plane (provided by the VMM), and the vhost-vsock device data
plane (provided by the host Linux kernel).

Using the vhost-vsock data plane, however, means that guest code gets to
control various inputs into the host kernel, thus obtaining a direct path to
exploiting any potential vulnerability affecting the vhost kernel code. This
wouldn't be compliant with the Firecracker security model - a new attack
surface would be added, providing the guest with a potential path to break
isolation. 

At the same time, VirtIO vsock is the most prevalent communication mechanism
employed by today's container orchestrators - an ecosystem with which
Firecracker aims to integrate, as a secure runtime, backed by hardware
virtualization.

## Proposed Approach

Our proposed solution is to provide full virtio-vsock support to software
running inside the guest VM, while bypassing vhost kernel code on the host. To
that end, Firecracker will implement the virtio-vsock device model, and mediate
communication between AF_UNIX sockets (on the host end) and AF_VSOCK sockets
(on the guest end). Both guest and host software will be able to use the
familiar socket interface.

In order to provide channel multiplexing, AF_VSOCK ports will be translated
into multiple AF_UNIX sockets (one unix socket per vsock port). Each vsock
device will have a unix socket path associated. E.g. `/path/to/vsock_{CID}`.
There are two scenarios to be considered, depending on where the connection is
initiated.

### Guest-Initiated Connections

When the virtio-vsock device model in Firecracker detects a connection
request coming from the guest (a VIRTIO_VSOCK_OP_REQUEST packet), it will try
to forward the connection to an AF_UNIX socket listening on the host, at
`/path/to/vsock_{CID}:{PORT}`, where `{PORT}` is the destination port, as
specified in the connection request packet. If no such socket exists, or
no one is listening on it, a connection cannot be established, and
a VIRTIO_VSOCK_OP_RST packet will be sent back to the guest.

From the user perspective, these would be the steps taken to establish a
communication channel:

1. Host: At VM configuration time, add a virtio-vsock device with `CID` and
   `PATH`;
2. Host: create and listen on an AF_UNIX socket at `{PATH}_{CID}:{PORT}`;
3. Guest: create an AF_VSOCK socket and issue a `connect()` call to `HOST_CID`
   and `PORT`;
4. Host: `accept()` the new connection.

The channel is established between the sockets obtained at steps 4 (host)
and 3 (guest).

### Host-Initiated Connections

Firecracker will be listening on an AF_UNIX socket, at `{PATH}_{CID}`. When
the host needs to initiate a connection, it will connect to that Unix socket,
then send a special *connect* data packet on it, specifying the destination
AF_VSOCK port. Following that, the same connection will be forwarded by
Firecracker to the guest software listening on that port, thus establishing
the requested channel. If no one is listening, Firecracker will terminate the
host connection.

1. Host: At VM configuration time, add a virtio-vsock device with `CID` and
   `PATH`;
2. Guest: create an AF_VSOCK socket and `listen()` on `PORT`;
3. Host: `connect()` to AF_UNIX at `{PATH}_{CID}`;
4. Host: `send()` *connect {PORT}* data packet on that connection;
5. Guest: `accept()` the new connection.

The channel is established between the sockets obtained at steps 3 (host)
and 5 (guest).

# Other Ideas

Multiple ideas have been considered and evaluated, before ariving at the
proposed solution. These ideas are listed below, together with a brief
description of their strong and weak points.

## Ethernet Host To Ethernet Guest

Using traditional network interfaces to communicate between guest and host
would require no implementation effort, but it also wouldn't be compliant
with our goal of providing a lightweight solution. Additional `netfilter`
rules would have to be set up on the host, for each microVM, in order to
enforce guest isolation. When considering our density goals, that means
the host would have to handle thousands of `netfilter` rules - a process
that puts too much strain on the host resources.

## Single Guest AF_VSOCK To Host AF_UNIX

A single-channel mechanism, that would offload multiplexing duties to the
user, similar to virtio-console. This would require the smallest
implementation effort, but would drastically increase the integration effort
needed from the Firecracker users.

## Hardened Full vhost-vsock Support

Firecracker would implement the standard vhost-vsock mechanism, while taking
two extra steps to ensure guest isolation:

- Intercept the guest to vhost communication via a man-in-the-middle
  approach, such that Firecracker appears as a guest driver to vhost, and as
  vhost to the guest driver; and
- Isolate the man-in-the-middle inside a separate process, such that any
  malicious guest, that would potentially take over the Firecracker process,
  would still be unable to directly control any input into the host kernel.

This would require the smallest integration effort from the Firecracker
users, since standard AF_VSOCK sockets would be supported on both the host
and the guest. However, it would also:

- require an extra host kernel dependency (vhost); and
- require complex data sanitization and isolation code to be implemented
  inside Firecracker, that would possibly constitute a new attack surface
  in itself.

## VirtIO-vsock Guest To Multiplexing Host Agent

Firecracker would provide full virtio-vsock support to software
running inside the guest VM, while bypassing vhost kernel code on the host. To
that end, Firecracker would implement the virtio-vsock device model, and require
that some additional userspace software (hereinafter called the host agent) be
present on the host, in order order to handle the vsock protocol specifics.
Firecracker would communicate with the host agent via a simple Unix domain
socket.

### The Host Agent

The Firecracker virtio-vsock device model will mediate communication between
the guest vsock driver and the host agent, *at the VirtIO level*. I.e.
Firecracker will handle the VirtIO queues for the vsock device, but will be
otherwise unaware of the vsock protocol specifics, which it will offload to the
host agent. This means that data packets traveling through the Unix domain
socket, between the host agent and the guest vsock driver, will be unaltered
vsock packets:

```C
struct virtio_vsock_packet { 
    struct virtio_vsock_hdr hdr; 
    u8 data[]; 
};

struct virtio_vsock_hdr { 
  le64 src_cid; 
  le64 dst_cid; 
  le32 src_port; 
  le32 dst_port; 
  le32 len; 
  le16 type; 
  le16 op; 
  le32 flags; 
  le32 buf_alloc; 
  le32 fwd_cnt; 
};
```

Since the host agent will have to implement non-trivial logic, such as flow
control and connection state handling, the amount of integration work required
from the Firecracker end users is increased considerably. To mitigate this
we would package the host agent as a standalone library, that would provide an API
similar to the traditional socket interface.

#### Pseudo-code Example

Illustrating this approach, below is a pseudo-code example of the general idea of
how this mechanism would appear to the Firecracker end user. This example
assumes a client running inside the guest VM, connecting to a server running on
the host, but the reverse would be quite similar:

```
           GUEST CODE / CLIENT              |         HOST CODE / SERVER
                                            |
// Standard socket interface to AF_VSOCK    |    // Use the Firecracker vsock lib
const HOST_CID = 2                          |
sk = socket(AF_VSOCK)                       |    import libfcvsock
sk.connect(HOST_CID, PORT_NUM)              |
sk.send("Hello world!")                     |    srv_sock = libfcvsock::socket()
sk.close()                                  |    srv_sock.listen(PORT_NUM)
                                            |    client_sock = srv_sock.accept()
                                            |    buf = client_sock.read()
                                            |
                                            |    // Will output "Hello world!"
                                            |    println(buf)
                                            |
                                            |    // Terminate connection
                                            |    client_sock.close()
```
