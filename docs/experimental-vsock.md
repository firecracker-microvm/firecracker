# Firecracker's experimental vsock support

Firecracker offers experimental **vhost-based vsock** support which allows
one or multiple vsock devices to be attached to the microVM. As per the
`vsock(7)` man page, *the VSOCK address family facilitates communication
between virtual machines and the host they are running on.
This address family is used by guest agents and hypervisor services that
need a communications channel that is independent of virtual machine network
configuration*.

## Obtaining the experimental binary

```cargo build --features vsock```

## Attaching a vsock device

```
curl --unix-socket /tmp/firecracker.socket -i \
     -X PUT "http://localhost/vsocks/root" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"id\": \"root\",
            \"guest_cid\": 3
         }"
```

- `id` is a string that uniquely identifies the current vsock device
- `guest_cid` represents an integer that must be `>=2` and `< UINT32_MAX`

## Limitations

Given that this is an experimental feature, we **do not** recommend including it
in production use. Enabling this vsock feature that is built on a vhost back-end
support adds an attack surface that bypasses the jailer barrier. In the near
future, we will add a non-vhost back-end for vsock. This feature is also not
covered by unit and integration tests.
