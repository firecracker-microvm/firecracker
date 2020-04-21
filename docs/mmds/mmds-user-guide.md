# microVM Metadata Service

The Firecracker microVM Metadata Service (MMDS) is a mutable data store which
can be used for sharing information between host and guests, in a secure and
easy at hand way.

# Activating the microVM Metadata Service

By default, MMDS is not reachable from the guest operating system. At microVM
runtime, MMDS is tightly coupled with a network interface, which allows MMDS
requests. When configuring the microVM, if MMDS needs to be activated, a
network interface has to be configured to allow MMDS requests. Network
interface configuration API can be found in the
[firecracker swagger file](../../src/api_server/swagger/firecracker.yaml).

### Example

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
      "allow_mmds_requests": true
    }'
```

# Configuring the microVM Metadata Service

MMDS can be configured pre-boot only, using the Firecracker API server. This
can be achieved through an HTTP `PUT` request to `/mmds/config` resource. The
complete MMDS configuration API is described in the 
[firecracker swagger file](../../src/api_server/swagger/firecracker.yaml).

At the moment, MMDS is configurable with respect to the IPv4 address used by
guest applications when issuing requests to MMDS. If MMDS configuration is not
provided before booting up the guest, the MMDS IPv4 address defaults to
`169.254.169.254`.

### Example

```bash
MMDS_IPV4_ADDR=169.254.170.2
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/mmds/config"     \
    -H "Content-Type: application/json"       \
    -d "{
             "ipv4_address": "${MMDS_IPV4_ADDR}"
    }"
```

MMDS is tightly coupled with a network interface which is used to route MMDS
packets. To send MMDS intended packets, guest applications must insert a new
rule into the routing table of the guest OS. This new rule must forward MMDS
intended packets to a network interface which allows MMDS requests.

### Example

```bash
MMDS_IPV4_ADDR=169.254.170.2
MMDS_NET_IF=eth0
ip route add ${MMDS_IPV4_ADDR} dev ${MMDS_NET_IF}
```

# Inserting and updating metadata

Inserting and updating metadata is possible through the Firecracker API server.
The metadata inserted in MMDS must be any valid JSON. An user can create or update
the MMDS data store before the microVM is started or during its operation. To
insert metadata into MMDS, an HTTP `PUT` request to the `/mmds` resource has to be
issued. This request must have a payload with metadata structured in
[JSON](https://tools.ietf.org/html/rfc7159) format. To replace existing metadata, a
subsequent HTTP `PUT` request to the `/mmds` resource must be issued, using as a
payload the new metadata. A complete description of metadata insertion firecracker
API can be found in the
[firecracker swagger file](../../src/api_server/swagger/firecracker.yaml).


### Example

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/mmds"            \
    -H "Content-Type: application/json"       \
    -d "{
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
    }"
```

To partially update existing metadata, an HTTP `PATCH` request to the `/mmds`
resource has to be issued, using as a payload the metadata patch, as
[JSON Merge Patch](https://tools.ietf.org/html/rfc7396) functionality
describes. A complete description of updating metadata Firecracker API can be
found in the [firecracker swagger file](../../src/api_server/swagger/firecracker.yaml).

### Example

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PATCH "http://localhost/mmds"          \
    -H "Content-Type: application/json"       \
    -d "{
            "latest": {
                  "meta-data": {
                       "ami-id": "ami-87654321",
                       "reservation-id": "r-79054aef",
                  }
            }
    }"
```

# Retrieving metadata

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

## Retrieving metadata in the host operating system

To retrieve existing MMDS metadata from host operating system, an HTTP `GET`
request to the `/mmds` resource must be issued. The HTTP response returns the
existing metadata, as a JSON formatted text. A complete description of
retrieving metadata Firecracker API can be found in the
[firecracker swagger file](../../src/api_server/swagger/firecracker.yaml).

### Example

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

## Retrieving metadata in the guest operating system

To retrieve existing MMDS metadata from guest operating system, an HTTP `GET`
request must be issued. The requested resource can be referenced by its
corresponding [JSON Pointer](https://tools.ietf.org/html/rfc6901), which is
also the path of the MMDS request. The HTTP response content will contain the
referenced metadata resource.

The response format can be JSON (experimental) or IMDS. The IMDS documentation
can be found [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).
The output format can be selected by specifying the optional `Accept` header.
Using `Accept: application/json` will format the output to JSON, while using
`Accept: plain/text` or not specifying this optional header at all will format
the output to IMDS.

Retrieving MMDS resources in IMDS format, other than JSON `string` and `object` types,
is not supported.

### Example

Retrieving the `latest/meta-data` resource in JSON format:
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

### Errors

*200* - `Ok`

The request was successfully processed and a response was successfully formed.

*400* - `Bad Request`

The request was malformed or it is not respecting the MMDS contract.

*404* - `Not Found`

The requested resource can not be found in the MMDS data store.

*405* - `Method Not Allowed`

The HTTP request uses a not allowed HTTP method and a response with the `Allow`
header was formed.

*501* - `Not Implemented`

The requested HTTP functionality is not supported by MMDS.

# Appendix

#### Example use case: credential rotation

For this example, the guest expects to find some sort of credentials (say, a
secret access key) by issuing a `GET` request to
`http://169.254.169.254/latest/meta-data/credentials/secret-key`. Most similar
use cases will encompass the following sequence of steps:

1. Some agent running on the host sends a `PUT` request with the initial
   contents of the MMDS, using the Firecracker API. This most likely takes
   place before the microVM starts running, but may also happen at a later
   time. Guest MMDS requests which arrive prior to contents being available
   receive a *NotFound* response.
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
via periodic polling, or some other mechanism. Since access to the data store
is thread safe, the guest can only receive either the old version, or the new
version of the key, and not some intermediate state caused by the update.
