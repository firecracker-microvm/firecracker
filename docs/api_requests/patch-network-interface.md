# Updating A Network Interface

After the microVM is started, the rate limiters assigned to a network
interface can be updated via a `PATCH /network-interfaces/{id}` API
call.

E.g. for a network interface created with:

```
PUT /network-interfaces/iface_1 HTTP/1.1
Host: localhost
Content-Type: application/json
Accept: application/json

{
    "iface_id": "iface_1",
    "host_dev_name": "fctap1",
    "guest_mac": "06:00:c0:a8:34:02",
    "rx_rate_limiter": {
        "bandwidth": {
            "size": 1024,
            "one_time_burst": 1048576,
            "refill_time": 1000
        }
    },
    "tx_rate_limiter": {
        "bandwidth": {
            "size": 1024,
            "one_time_burst": 1048576,
            "refill_time": 1000
        }
    }
}
```

A `PATCH` request can be sent at any future time, to update the rate
limiters:

```
PATCH /network-interfaces/iface_1 HTTP/1.1
Host: localhost
Content-Type: application/json
Accept: application/json

{
    "iface_id": "iface_1",
    "rx_rate_limiter": {
        "bandwidth": {
            "size": 1048576,
            "refill_time": 1000
        },
        "ops": {
            "size": 2000,
            "refill_time": 1000
        }
    }
}
```

The full specification of the data structures available for this call can be
found in our [OpenAPI spec](../../src/api_server/swagger/firecracker.yaml).

**Note**: The data provided for the update is merged with the existing data.
In the above example, the RX rate limit is updated, but the TX rate limit
remains unchanged.


# Removing Rate Limiting

A rate limit can be disabled by providing a 0-sized token bucket. E.g.,
following the above example, the TX rate limit can be disabled with:


```
PATCH /network-interfaces/iface_1 HTTP/1.1
Host: localhost
Content-Type: application/json
Accept: application/json

{
    "iface_id": "iface_1",
    "tx_rate_limiter": {
        "bandwidth": {
            "size": 0,
            "refill_time": 0
        },
        "ops": {
            "size": 0,
            "refill_time": 0
        }
    }
}
```
