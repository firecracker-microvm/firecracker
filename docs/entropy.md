# Using the Firecracker entropy device

## What is the entropy device

An entropy device is a [`virtio-rng` device][1] that provides guests with
"high-quality randomness for guest use". Guests issue requests in the form of a
buffer that will be filled with random bytes from the device. The source of
random bytes that the device will use to fill the buffers is an implementation
decision.

On the guest side, the kernel uses random bytes received through the device
as an extra source of entropy. Moreover, the guest VirtIO driver exposes the
`/dev/hwrng` character device. User-space applications can use this device to
request random bytes from the device.

## Firecracker implementation

Firecracker offers the option of attaching a single `virtio-rng` device. Users
can configure it through the `/entropy` API endpoint. The request body includes
a single (optional) parameter for configuring a rate limiter.

For example, users can configure the entropy device with a bandwidth rate
limiter of 10KB/sec like this:

```console
curl --unix-socket $socket_location -i \
    -X PUT 'http://localhost/entropy' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d "{
        \"rate_limiter\": {
            \"bandwidth\": {
                \"size\": 1000,
                \"one_time_burst\": 0,
                \"refill_time\": 100
            }
        }
    }"
```

If a configuration file is used for configuring a microVM, the same setup can
be achieved by adding a section like this:

```json
"entropy": {
    "rate_limiter": {
        "bandwidth" {
            "size": 1000,
            "one_time_burst": 0,
            "refill_time": 100
        }
    }
}
```

On the host side, Firecracker relies on [`aws-lc-rs`][2] to retrieve the random bytes.
`aws-lc-rs` uses the [`AWS-LC` cryptographic library][3].

## Prerequisites

In order to use the entropy device, users must use a kernel with the
`virtio-rng` front-end driver compiled in or loaded as a module. The relevant
kernel configuration option is `CONFIG_HW_RANDOM_VIRTIO` (which depends on
`CONFIG_HW_RANDOM` and `CONFIG_VIRTIO`).

[1]: https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-3050004
[2]: https://docs.rs/aws-lc-rs/latest/aws_lc_rs/index.html
[3]: https://github.com/aws/aws-lc
