# microVM Metadata Service

The Firecracker microVM Metadata Service (MMDS) is a mutable data store which
can be used for sharing information between host and guests, in a secure and
easy at hand way.

## Configuring and activating the microVM Metadata Service

By default, MMDS is not reachable from the guest operating system. At microVM
runtime, MMDS is tightly coupled with a network interface, which allows MMDS
requests. When configuring the microVM, if MMDS needs to be activated, a network
interface has to be configured to allow MMDS requests. This can be achieved in
two steps:

1. Attach one (or more) network interfaces through an HTTP `PUT` request to
   `/network-interfaces/${MMDS_NET_IF}`. The full network configuration API can
   be found in the
   [firecracker swagger file](../../src/firecracker/swagger/firecracker.yaml).
1. Configure MMDS through an HTTP `PUT` request to `/mmds/config` resource and
   include the IDs of the network interfaces that should allow forwarding
   requests to MMDS in the `network_interfaces` list. The complete MMDS API is
   described in the
   [firecracker swagger file](../../src/firecracker/swagger/firecracker.yaml).

### Examples

Attaching a network device with ID `MMDS_NET_IF`:

```bash
MMDS_NET_IF=eth0
curl --unix-socket /tmp/firecracker.socket -i                 \
  -X PUT 'http://localhost/network-interfaces/${MMDS_NET_IF}' \
  -H 'Accept: application/json'                               \
  -H 'Content-Type: application/json'                         \
  -d '{
      "iface_id": "${MMDS_NET_IF}",
      "guest_mac": "AA:FC:00:00:00:01",
      "host_dev_name": "tap0"
    }'
```

Configuring MMDS to receive requests through the `MMDS_NET_IF` network interface
ID:

```bash
MMDS_IPV4_ADDR=169.254.170.2
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/mmds/config"     \
    -H "Content-Type: application/json"       \
    -d '{
             "network_interfaces": ["${MMDS_NET_IF}"]
    }'
```

MMDS can be configured pre-boot only, using the Firecracker API server. Enabling
MMDS without at least a network device attached will return an error.

The IPv4 address used by guest applications when issuing requests to MMDS can be
customized through the same HTTP `PUT` request to `/mmds/config` resource, by
specifying the IPv4 address to the `ipv4_address` field. If the IP configuration
is not provided before booting up the guest, the MMDS IPv4 address defaults to
`169.254.169.254`.

```bash
MMDS_IPV4_ADDR=169.254.170.2
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/mmds/config"     \
    -H "Content-Type: application/json"       \
    -d '{
             "network_interfaces": ["${MMDS_NET_IF}"],
             "ipv4_address": "${MMDS_IPV4_ADDR}"
    }'
```

MMDS is tightly coupled with a network interface which is used to route MMDS
packets. To send MMDS intended packets, guest applications must insert a new
rule into the routing table of the guest OS. This new rule must forward MMDS
intended packets to a network interface which allows MMDS requests. For example:

```bash
MMDS_IPV4_ADDR=169.254.170.2
MMDS_NET_IF=eth0
ip route add ${MMDS_IPV4_ADDR} dev ${MMDS_NET_IF}
```

MMDS supports two methods to access the contents of the metadata store from the
guest operating system: `V1` and `V2`. More about the particularities of the two
mechanisms can be found in the
[Retrieving metadata in the guest operating system](#retrieving-metadata-in-the-guest-operating-system)
section. The MMDS version used can be specified when configuring MMDS, through
the `version` field of the HTTP `PUT` request to `/mmds/config` resource.
Accepted values are `V1`(deprecated) and `V2` and the default MMDS version used
in case the `version` field is missing is [Version 1](#version-1-deprecated).

```bash
MMDS_IPV4_ADDR=169.254.170.2
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/mmds/config"     \
    -H "Content-Type: application/json"       \
    -d '{
             "network_interfaces": ["${MMDS_NET_IF}"],
             "version": "V2",
             "ipv4_address": "${MMDS_IPV4_ADDR}"
    }'
```

## Inserting and updating metadata

Inserting and updating metadata is possible through the Firecracker API server.
The metadata inserted in MMDS must be any valid JSON. A user can create or
update the MMDS data store before the microVM is started or during its
operation. To insert metadata into MMDS, an HTTP `PUT` request to the `/mmds`
resource has to be issued. This request must have a payload with metadata
structured in [JSON](https://tools.ietf.org/html/rfc7159) format. To replace
existing metadata, a subsequent HTTP `PUT` request to the `/mmds` resource must
be issued, using as a payload the new metadata. A complete description of
metadata insertion firecracker API can be found in the
[firecracker swagger file](../../src/firecracker/swagger/firecracker.yaml).

An example of an API request for inserting metadata is provided below:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/mmds"            \
    -H "Content-Type: application/json"       \
    -d '{
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
    }'
```

To partially update existing metadata, an HTTP `PATCH` request to the `/mmds`
resource has to be issued, using as a payload the metadata patch, as
[JSON Merge Patch](https://tools.ietf.org/html/rfc7396) functionality describes.
A complete description of updating metadata Firecracker API can be found in the
[firecracker swagger file](../../src/firecracker/swagger/firecracker.yaml).

An example API for how to update existing metadata is offered below:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PATCH "http://localhost/mmds"          \
    -H "Content-Type: application/json"       \
    -d '{
            "latest": {
                  "meta-data": {
                       "ami-id": "ami-87654321",
                       "reservation-id": "r-79054aef",
                  }
            }
    }'
```

## Retrieving metadata

MicroVM metadata can be retrieved both from host and guest operating systems.
For the scope of this chapter, let's assume the data store content is the JSON
below:

```json
{
    "latest": {
          "meta-data": {
               "ami-id": "ami-87654321",
               "reservation-id": "r-79054aef"
          }
    }
}
```

### Retrieving metadata in the host operating system

To retrieve existing MMDS metadata from host operating system, an HTTP `GET`
request to the `/mmds` resource must be issued. The HTTP response returns the
existing metadata, as a JSON formatted text. A complete description of
retrieving metadata Firecracker API can be found in the
[firecracker swagger file](../../src/firecracker/swagger/firecracker.yaml).

Below you can see how to retrieve metadata from the host:

```bash
curl -s --unix-socket /tmp/firecracker.socket http://localhost/mmds
```

Output:

```json
{
    "latest": {
          "meta-data": {
               "ami-id": "ami-87654321",
               "reservation-id": "r-79054aef"
          }
    }
}
```

### Retrieving metadata in the guest operating system

Accessing the contents of the metadata store from the guest operating system can
be done using one of the following methods:

- `V1`: simple request/response method (deprecated)
- `V2`: session-oriented method

#### Version 1 (Deprecated)

**Version 1 is deprecated and will be removed in the next major version change.
Version 2 should be used instead.**

To retrieve existing MMDS metadata using MMDS version 1, an HTTP `GET` request
must be issued. The requested resource can be referenced by its corresponding
[JSON Pointer](https://tools.ietf.org/html/rfc6901), which is also the path of
the MMDS request. The HTTP response content will contain the referenced metadata
resource.

As in version 2, version 1 also supports a session oriented method in order to
make the migration easier. See [the next section](#version-2) for the session
oriented method. Note that version 1 returns a successful response to a `GET`
request even with an invalid token or no token not to break existing workloads.
`mmds.rx_invalid_token` and `mmds.rx_no_token` metrics track the number of `GET`
requests with invalid tokens and missing tokens respectively, helping users
evaluate their readiness for migrating to MMDS version 2.

Requests containing any other HTTP methods than `GET` and `PUT` will receive
**405 Method Not Allowed** error.

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER_OBJ=latest/meta-data
curl -s "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER_OBJ}"
```

#### Version 2

Similar to
[IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html),
MMDS version 2 (`V2`) is a session oriented method, which makes use of a session
token in order to allow fetching metadata contents.

The session must start with an HTTP `PUT` request that generates the session
token. In order to be successful, the request must respect the following
constraints:

- must be directed towards `/latest/api/token` path
- must contain a `X-metadata-token-ttl-seconds` or
  `X-aws-ec2-metadata-token-ttl-seconds` header specifying the token lifetime in
  seconds. The value cannot be lower than 1 or greater than 21600 (6 hours).
- must not contain a `X-Forwarded-For` header.

```bash
MMDS_IPV4_ADDR=169.254.170.2
TOKEN=`curl -X PUT "http://${MMDS_IPV4_ADDR}/latest/api/token" \
      -H "X-metadata-token-ttl-seconds: 21600"`
```

The HTTP response from MMDS is a plaintext containing the session token.

During the duration specified by the token's time to live value, all subsequent
`GET` requests must specify the session token through the `X-metadata-token` or
`X-aws-ec2-metadata-token` header in order to fetch data from MMDS.

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER_OBJ=latest/meta-data
curl -s "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER_OBJ}" \
    -H "X-metadata-token: ${TOKEN}"
```

After the token expires, it becomes unusable and a new session token must be
issued.

##### Snapshotting considerations

The data store is **not** persisted across snapshots, in order to avoid leaking
vm-specific information that may need to be reseeded into the data store for a
new clone.

The MMDS version, network stack configuration and IP address used for accessing
the service are persisted across snapshot-restore.

If the targeted snapshot version does not support Mmds Version 2, it will not be
persisted in the snapshot (the clone will use the default, V1). Similarly, if a
snapshotted Vm state contains the Mmds version but the Firecracker version used
for restoring does not support persisting the version, the default will be used.

### MMDS formats

The response format can be JSON or IMDS. The IMDS documentation can be found
[here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).
The output format can be selected by specifying the optional `Accept` header.
Using `Accept: application/json` will format the output to JSON, while using
`Accept: plain/text` or not specifying this optional header at all will format
the output to IMDS. Setting `imds_compat` to `true` through PUT request to
`/mmds/config` enforces MMDS to always respond in IMDS format regardless of the
`Accept` header. This allows code written to work on EC2 IMDS to also work on
Firecracker MMDS.

Retrieving MMDS resources in IMDS format, other than JSON `string` and `object`
types, is not supported.

Below is an example on how to retrieve the `latest/meta-data` resource in JSON
format:

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER_OBJ=latest/meta-data
curl -s -H "Accept: application/json" "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER_OBJ}"
```

Output:

```json
{
    "ami-id": "ami-87654321",
    "reservation-id": "r-79054aef"
}
```

Retrieving the `latest/meta-data/ami-id` resource in JSON format:

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER_STR=latest/meta-data/ami-id
curl -s -H "Accept: application/json" "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER_STR}"
```

Output:

```json
"ami-87654321"
```

Retrieving the `latest` resource in IMDS format:

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER=latest
curl -s "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER}"
```

Output:

```text
meta-data/
```

Retrieving the `latest/meta-data/` resource in IMDS format:

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER=latest/meta-data
curl -s "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER}"
```

Output:

```text
ami-id
reservation-id
```

Retrieving the `latest/meta-data/ami-id` resource in IMDS format:

```bash
MMDS_IPV4_ADDR=169.254.170.2
RESOURCE_POINTER=latest/meta-data/ami-id
curl -s "http://${MMDS_IPV4_ADDR}/${RESOURCE_POINTER}"
```

Output:

```text
ami-87654321
```

## Errors

*200* - `Ok`

The request was successfully processed and a response was successfully formed.

*400* - `Bad Request`

The request was malformed.

*401* - `Unauthorized`

Only when using MMDS `V2`. The HTTP request either lacks the session token, or
the token specified is invalid. A token is invalid if it was not generated using
an HTTP `PUT` request or if it has expired.

*404* - `Not Found`

The requested resource can not be found in the MMDS data store.

*405* - `Method Not Allowed`

The HTTP request uses a not allowed HTTP method and a response with the `Allow`
header was formed. When using MMDS `V1`, this is returned for any HTTP method
other than `GET`. When MMDS `V2` is configured, the only accepted HTTP methods
are `PUT` and `GET`.

*501* - `Not Implemented`

The requested HTTP functionality is not supported by MMDS or the requested
resource is not supported in IMDS format.

## Appendix

### Example use case: credential rotation

For this example, the guest expects to find some sort of credentials (say, a
secret access key) by issuing a `GET` request to
`http://169.254.169.254/latest/meta-data/credentials/secret-key`. Most similar
use cases will encompass the following sequence of steps:

1. Some agent running on the host sends a `PUT` request with the initial
   contents of the MMDS, using the Firecracker API. This most likely takes place
   before the microVM starts running, but may also happen at a later time. Guest
   MMDS requests which arrive prior to contents being available receive a
   *NotFound* response.
1. The contents are saved to MMDS.
1. The guest sends a `GET` request for the secret key, which is intercepted by
   MMDS.
1. MMDS processes the request and sends back an HTTP response with the ensembled
   secret key as a JSON string.

After a while, the host agent decides to rotate the secret key. It does so by
updating the data store with a new value. This can be done via a `PUT` request
to the `/mmds` API resource, which replaces everything, or with a `PATCH`
request that only touches the desired key. This effectively triggers the first
two steps again.

The guest reads the new secret key, going one more time through the last three
steps. This can happen after a notification from the host agent, or discovered
via periodic polling, or some other mechanism. Since access to the data store is
thread safe, the guest can only receive either the old version, or the new
version of the key, and not some intermediate state caused by the update.
