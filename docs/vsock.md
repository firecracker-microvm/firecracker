# Using the Firecracker Virtio-vsock Device

## Table of Contents

- [Prerequisites](#prerequisites)
- [Firecracker Virtio-vsock Design](#firecracker-virtio-vsock-design)
- [Setting up the Virtio-vsock Device](#setting-up-the-virtio-vsock-device)
- [Examples](#examples)

## Prerequisites

This document assumes the reader is familiar with running Firecracker and
issuing API commands over its API socket. For a more details on how to run
Firecracker, check out the [getting started guide](getting-started.md).

Familiarity with socket programming, in particular Unix sockets, is also
assumed.

## Firecracker Virtio-vsock Design

The Firecracker vsock device aims to provide full virtio-vsock support to
software running inside the guest VM, while bypassing vhost kernel code on the
host. To that end, Firecracker implements the virtio-vsock device model, and
mediates communication between AF_UNIX sockets (on the host end) and AF_VSOCK
sockets (on the guest end).

In order to provide channel multiplexing the guest `AF_VSOCK` ports are mapped
1:1 to `AF_UNIX` sockets on the host. The virtio-vsock device must be
configured with a path to an `AF_UNIX` socket on the host (e.g.
`/path/to/v.sock`). There are two scenarios to be considered, depending on
where the connection is initiated.

### Host-Initiated Connections

When a microvm having a vsock device attached is started, Firecracker will
begin listening on an AF_UNIX socket (e.g. `/path/to/v.sock`). When the host
needs to initiate a connection, it should connect to that Unix socket, then
send a connect command, in text form, specifying the destination AF_VSOCK port:
"CONNECT PORT\n". Where PORT is the decimal port number, and "\n" is EOL (ASCII
0x0A). Following that, the same connection will be forwarded by Firecracker to
the guest software listening on that port, thus establishing the requested
channel. If the connection has been established, Firecracker will send an
acknowledgement message to the connecting end (host-side), in the form
"OK PORT\n", where `PORT` is the vsock port number assigned to
the host end. If no one is listening, Firecracker will terminate the host
connection.

Client A initiates connection to Server A in [figure below](#vsock-connections):

1. Host: At VM configuration time, add a virtio-vsock device, with some path
   specified in `uds_path`;
2. Guest: create an AF_VSOCK socket and `listen()` on `<port_num>`;
3. Host: `connect()` to AF_UNIX at `uds_path`.
4. Host: `send()` "CONNECT <port_num>\n".
5. Guest: `accept()` the new connection.
6. Host: `read()` "OK <assigned_hostside_port>\n".

The channel is established between the sockets obtained at steps 3 (host)
and 5 (guest).

### Guest-Initiated Connections

When the virtio-vsock device model in Firecracker detects a connection request
coming from the guest (a VIRTIO_VSOCK_OP_REQUEST packet), it tries to forward
the connection to an AF_UNIX socket listening on the host, at
`/path/to/v.sock_PORT` (or whatever path was configured via the `uds_path`
property of the vsock device), where `PORT` is the destination port (in
decimal), as specified in the connection request packet. If no such socket
exists, or no one is listening on it, a connection cannot be established, and a
VIRTIO_VSOCK_OP_RST packet will be sent back to the guest.

Client B initiates connection to Server B in [figure below](#vsock-connections):

1. Host: At VM configuration time, add a virtio-vsock device, with some
   `uds_path` (e.g. `/path/to/v.sock`).
2. Host: create and listen on an AF_UNIX socket at `/path/to/v.sock_PORT`.
3. Guest: create an AF_VSOCK socket and connect to `HOST_CID` (i.e. integer
   value 2) and `PORT`;
4. Host: `accept()` the new connection.

The channel is established between the sockets obtained at steps 4 (host)
and 3 (guest).

![Vsock Connections](
images/vsock-connections.png?raw=true
"Vsock Connections")

## Setting up the virtio-vsock device

The virtio-vsock device will require an ID, a CID, and the path to a backing
AF_UNIX socket:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/vsock' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
      "vsock_id": "1",
      "guest_cid": 3,
      "uds_path": "./v.sock"
  }'
```

Once the microvm is started, Firecracker will create and start listening on the
AF_UNIX socket at `uds_path`. Incoming connections will get forwarded to the
guest microvm, and translated to AF_VSOCK. The destination port is expected to
be specified by sending the text command "CONNECT <port_num>\n", immediately
after the AF_UNIX connection is established. Connections initiated from within
the guest will be forwarded to AF_UNIX sockets expected to be listening at
`./v.sock_<port_num>`. I.e. a guest connection to port 52 will get forwarded to
`./v.sock_52`.

## Examples

The examples below assume a running microvm, with a vsock device configured as
shown [above](#setting-up-the-virtio-vsock-device).


### Using External Socket Tools (`nc-vsock` and `socat`)

#### Connecting From Host to Guest

First, make sure the vsock port is bound and listened to on the guest side.
Say, port 52:

```bash
$ nc-vsock -l 52
```

On the host side, connect to `./v.sock` and issue a connection request to that
port:

```bash
$ socat - UNIX-CONNECT:./v.sock
CONNECT 52
```

`socat` will display the connection acknowledgement message:

```
OK 1073741824
```

The connection should now be established (in the above example, between
`nc-vsock` on the guest side, and `socat` on the host side).

#### Connecting From Guest To Host

First make sure the AF_UNIX corresponding to your desired port is listened to
on the host side:

```bash
$ socat - UNIX-LISTEN:./v.sock_52
```

On the guest side, create an AF_VSOCK socket and connect it to the previously
chosen port on the host (CID=2):

```bash
$ nc-vsock 2 52
```
