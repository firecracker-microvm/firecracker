# microVM Metadata Service

MMDS consists of three major logical components: the backend, the data store,
and the minimalist HTTP/TCP/IPv4 stack (named *Dumbo*). They all exist within
the Firecracker process, and outside the KVM boundary; the first is a part of
the API server, the data store is a global entity for a single microVM, and the
last is a part of the device model.

## The MMDS backend

Users can add/update the MMDS contents via the backend, which is accessible
through the Firecracker API. Setting the initial contents involves a `PUT`
request to the `/mmds` API resource, with a JSON body that describes the
desired data store structure and contents. Here's a JSON example:

```json
{
"latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
                "network": {
                    "interfaces": {
                        "macs": {
                            "02:29:96:8f:6a:2d": {
                                "device-number": "13345342",
                                "local-hostname": "localhost",
                                "subnet-id": "subnet-be9b61d"
                            }
                        }
                    }
                }
            }
        }
}
```

The MMDS contents can be updated either via a subsequent `PUT` (that replaces them
entirely), or using `PATCH` requests, which feed the JSON body into the JSON Merge
Patch functionality, based on [RFC 7396](https://tools.ietf.org/html/rfc7396). MMDS
related API requests come from the host, which is considered a trusted environment,
so there are no checks beside the kind of validation done by HTTP server and
`serde-json` (the crate used to de/serialize JSON). Most importantly, there is
currently a maximum request payload size, limited to 256KB; this limitation is
present because the HTTP server uses memory to backup the request payload.
If the payload gets bigger than 256KB, it will issue a `mremap` syscall, which is
blacklisted by the default seccomp rules. MMDS contents can be retrieved using the
Firecracker API, via a `GET` request to the `/mmds` resource.

## The data store

This is a global data structure, currently referenced using a global variable,
that represents the strongly-typed version of JSON-based user input describing
the MMDS contents. It leverages the recursive
[Value](https://docs.serde.rs/serde_json/value/enum.Value.html) type exposed by
`serde-json`. It can only be accessed from thread-safe contexts. MMDS data
store supports at the moment storing and retrieving JSON values. Data store
contents can be retrieved using the Firecracker API server from host and using
the embedded MMDS HTTP/TCP/IPv4 network stack from guest.

## Dumbo

The *Dumbo* HTTP/TCP/IPv4 network stack handles guest HTTP requests heading
towards the configured MMDS IPv4 address. Before going into *Dumbo* specifics,
it's worth going through a brief description of the Firecracker network device
model. Firecracker only offers Virtio-net paravirtualized devices to guests.
Drivers running in the guest OS use ring buffers in a shared memory area to
communicate with the device model when sending or receiving frames. The device
model associates each guest network device with a TAP device on the host.
Frames sent by the guest are written to the TAP fd, and frames read from the
TAP fd are handed over to the guest.

The *Dumbo* stack can be instantiated once for every network device, and is
disabled by default. It can be enabled by setting the value of the
`allow_mmds_requests` parameter to `true` in the API request body used to
attach a guest network device. Once enabled, the stack taps into the
aforementioned data path. Each frame coming from the guest is examined to
determine whether it should be processed by *Dumbo* instead of being written to
the TAP fd. Also, every time there is room in the ring buffer to hand over
frames to the guest, the device model first checks whether *Dumbo* has anything
to send; if not, it resumes getting frames from the TAP fd (when available).

We chose to implement our own solution, instead of leveraging existing
libraries/implementations, because responding to guest MMDS queries in the
context of Firecracker is amenable to a wide swath of simplifications.
First of all, we only need to handle `GET` requests, which require a bare-bones
HTTP 1.1 server, without support for most headers and more advanced features
like chunking. Also, we get to choose what subset of HTTP is used when building
responses. Moving lower in the stack, we are dealing with TCP connections over
what is essentially a point-to-point link, that seldom loses packets and does
not reorder them. This means we can do away with congestion control
(we only use flow control), complex reception logic, and support for most TCP
options/features. At this point, the layers below (Ethernet and IPv4) don't
involve much more than sanity checks of frame/packet contents.

*Dumbo* is built using both general purpose components (which we plan to offer
as part of one or more libraries), and Firecracker MMDS specific code. The
former category consists of various helper modules used to process streams of
bytes as protocol data units (Ethernet & ARP frames, IPv4 packets, and TCP
segments), a TCP handler which listens for connections while demultiplexing
incoming segments, a minimalist TCP connection endpoint implementation, and a
greatly simplified HTTP 1.1 server. The Firecracker MMDS specific code is found
in the logic which taps into the device model, and the component that parses an
HTTP request, builds a response based on MMDS contents, and finally sends back
a reply.

### MMDS Network Stack

Somewhat confusingly, this is the name of the component which taps the device
model. It has a user-configured IPv4 address (see 
[Firecracker MMDS configuration API](../../src/api_server/swagger/firecracker.yaml))
and MAC (`06:01:23:45:67:01`) addresses. The latter is also used to respond to ARP requests.
For every frame coming from the guest, the following steps take place:

1. Apply a heuristic to determine whether the frame may contain an ARP request
   for the MMDS IP address, or an IPv4 packet heading towards the same address.
   There can be no false negatives. Frames that fail both checks are *rejected*
   (deferred to the device model for regular processing).
1. *Reject* invalid Ethernet frames. *Reject* valid frames if their EtherType
   is neither ARP, nor IPv4.
1. (**if EtherType == ARP**) *Reject* invalid ARP frames. *Reject* the frame if
   its target protocol address field is different from the MMDS IP address.
   Otherwise, record that an ARP request has been received (the stack only
   remembers the most recent request).
1. (**if EtherType == IPv4**) *Reject* invalid packets. *Reject* packets if
   their destination address differs from the MMDS IP address. *Drop* (stop
   processing without deferring to the device model) packets that do not carry
   TCP segments (by looking at the protocol number field). Send the rest to the
   inner TCP handler.

The current implementation does not support Ethernet 802.1Q tags, and does not
handle IP fragmentation. Tagged Ethernet frames are most likely going to be
deferred to the device model for processing, because the heuristics do not take
the presence of the tag into account. Moreover, their EtherType will not appear
to be of interest. Fragmented IP packets do not get reassembled; they are
treated as independent packets.

Whenever the guest is able to receive a frame, the device model first requests
one from the MMDS network stack associated with the current network device.

1. If an ARP request has been previously recorded, send an ARP reply and forget
   about the request.
1. If the inner TCP handler has any packets to transmit, wrap the next one into
   a frame and send it.
1. There are no MMDS related frames to send, so tell the device model to read
   from the TAP fd instead.

### TCP handler

Handles received packets that appear to carry TCP segments. Its operation is
described in the `dumbo` crate documentation. Each connection is associated
with an MMDS endpoint.

### MMDS endpoint

This component gets the byte stream from an inner TCP connection object,
identifies the boundaries of the next HTTP request, and parses it using an
HttpRequest object. For each valid `GET` request, the URI is used to identify
a key from the metadata store (like in the previous example), and a response is
built using the Firecracker implementation of HttpResponse logic, based on the
associated value, and sent back to the guest over the same connection. Each
endpoint has a fixed size receive buffer, and a variable length response buffer
(depending on the size of each response). TCP receive window semantics are used
to ensure the guest does not overrun the receive buffer during normal operation
(the connection has to drop segments otherwise). There can be at most one
response pending at any given time.

Here are more details describing what happens when a segment is received by an
MMDS endpoint (previously created when a SYN segment arrived at the TCP
handler):

1. Invoke the receive functionality of the inner connection object, and append
   any new data to the receive buffer.
1. If no response is currently pending, attempt to identify the end of the
   first request in the receive buffer. If no such boundary can be found, and
   the buffer is full, reset the inner connection (which also causes the
   endpoint itself to be subsequently removed) because the guest exceeded the
   maximum allowed request size.
1. If no response is pending, and we can identify a request in the receive
   buffer, parse it, free up the associated buffer space (also update the
   connection receive window), and build an HTTP response, which becomes the
   current pending response.
1. If a FIN segment was received, and there's no pending response, call `close`
   on the inner connection. If a valid RST is received at any time, mark the
   endpoint for removal.

When the TCP handler asks an MMDS endpoint for any segments to send, the
transmission logic of the inner connection is invoked, specifying the pending
response (when present) as the payload source.

### Connection

Connection objects are minimalist implementation of the TCP protocol. They are
used to reassemble the byte stream which carries guest HTTP requests, and to
send back segments which contain parts of the response. More details are
available in the `dumbo` crate documentation.
