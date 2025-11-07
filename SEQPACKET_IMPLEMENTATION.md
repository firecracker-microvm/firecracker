# SEQPACKET Socket Type Implementation for Firecracker Vsock

## Overview

This document describes the implementation of SEQPACKET socket type support for Firecracker's vsock device, addressing GitHub Issue #4822.

## Background

The virtio vsock specification (v1.2+) introduced `VIRTIO_VSOCK_F_SEQPACKET` as an optional feature flag to support SEQPACKET socket type. This enables VMs to relay datagrams over vsock while preserving message boundaries, which is not possible with SOCK_STREAM connections that combine data together.

## Implementation Details

### Feature Flag

The `VIRTIO_VSOCK_F_SEQPACKET` feature flag is advertised in the device capabilities:

```rust
// src/vmm/src/devices/virtio/vsock/device.rs
pub(crate) const VIRTIO_VSOCK_F_SEQPACKET: u64 = 1;
pub(crate) const AVAIL_FEATURES: u64 =
    (1 << VIRTIO_F_VERSION_1 as u64) | 
    (1 << VIRTIO_F_IN_ORDER as u64) | 
    (1 << VIRTIO_VSOCK_F_SEQPACKET);
```

### Socket Type Constants

Two socket types are supported:

```rust
// src/vmm/src/devices/virtio/vsock/mod.rs
pub const VSOCK_TYPE_STREAM: u16 = 1;      // Connection-oriented stream
pub const VSOCK_TYPE_SEQPACKET: u16 = 2;   // Connection-oriented with message boundaries
```

### Connection Management

#### VsockConnection Structure

Each connection stores its socket type:

```rust
pub struct VsockConnection<S: VsockConnectionBackend> {
    socket_type: u16,  // VSOCK_TYPE_STREAM or VSOCK_TYPE_SEQPACKET
    // ... other fields
}
```

#### Packet Validation

The muxer validates socket types for incoming packets:

```rust
// src/vmm/src/devices/virtio/vsock/unix/muxer.rs
if pkt.hdr.type_() != uapi::VSOCK_TYPE_STREAM
    && pkt.hdr.type_() != uapi::VSOCK_TYPE_SEQPACKET
{
    self.enq_rst(pkt.hdr.dst_port(), pkt.hdr.src_port());
    return Ok(());
}
```

### Host-Initiated Connections

#### CONNECT Command Format

The CONNECT command now supports an optional socket type parameter:

```
CONNECT <port> [STREAM|SEQPACKET]\n
```

Examples:
- `CONNECT 1234\n` - Defaults to STREAM (backward compatible)
- `CONNECT 1234 STREAM\n` - Explicit STREAM type
- `CONNECT 1234 SEQPACKET\n` - SEQPACKET type

#### Parsing Implementation

```rust
fn read_local_stream_port(stream: &mut UnixStream) -> Result<(u32, u16), VsockUnixBackendError> {
    // ... read and parse command ...
    
    let socket_type = match word_iter.next() {
        Some(type_str) => match type_str.to_uppercase().as_str() {
            "STREAM" => uapi::VSOCK_TYPE_STREAM,
            "SEQPACKET" => uapi::VSOCK_TYPE_SEQPACKET,
            _ => return Err(VsockUnixBackendError::InvalidPortRequest),
        },
        None => uapi::VSOCK_TYPE_STREAM, // Default to STREAM for backward compatibility
    };
    
    Ok((port, socket_type))
}
```

### Guest-Initiated Connections

For guest-initiated connections, the socket type is extracted from the vsock packet header:

```rust
fn handle_peer_request_pkt(&mut self, pkt: &VsockPacketTx) {
    // ... connection setup ...
    
    MuxerConnection::new_peer_init(
        stream,
        uapi::VSOCK_HOST_CID,
        self.cid,
        pkt.hdr.dst_port(),
        pkt.hdr.src_port(),
        pkt.hdr.buf_alloc(),
        pkt.hdr.type_(),  // Socket type from packet header
    )
}
```

## Usage Example

### From Guest VM (using Rust)

```rust
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
use nix::sys::socket::{connect, SockaddrVsock};

// Create SEQPACKET socket
let socket_fd = socket(
    AddressFamily::Vsock,
    SockType::SeqPacket,
    SockFlag::empty(),
    None
)?;

// Connect to host
let addr = SockaddrVsock::new(2, 500); // CID 2 = host, port 500
connect(socket_fd, &addr)?;
```

### From Host (using Unix Domain Socket)

```bash
# Connect to guest port 500 with SEQPACKET type
echo "CONNECT 500 SEQPACKET" | nc -U /path/to/vsock.sock
```

## Testing

Comprehensive tests have been added to verify SEQPACKET functionality:

### Test Coverage

1. **test_seqpacket_socket_type**: Guest-initiated SEQPACKET connection
2. **test_seqpacket_host_initiated**: Host-initiated SEQPACKET connection
3. **test_seqpacket_backward_compatibility**: CONNECT without type defaults to STREAM
4. **test_seqpacket_explicit_stream**: Explicit STREAM type specification
5. **test_seqpacket_data_transfer**: Data transfer over SEQPACKET connection

### Running Tests

```bash
# Run all vsock tests
cargo test --package vmm --lib devices::virtio::vsock::unix::muxer

# Run specific SEQPACKET tests
cargo test --package vmm --lib test_seqpacket
```

## Backward Compatibility

The implementation maintains full backward compatibility:

- CONNECT commands without a socket type parameter default to STREAM
- Existing applications continue to work without modification
- The feature flag allows guests to detect SEQPACKET support

## Socket Type Validation

The implementation enforces socket type consistency:

1. **Packet validation**: Rejects packets with unsupported socket types (sends RST)
2. **Connection tracking**: Each connection maintains its socket type
3. **Type propagation**: Socket type is preserved in all packet headers

## Limitations

1. **No socket type conversion**: Once a connection is established with a specific socket type, it cannot be changed
2. **Host-side socket matching**: The host application must create a Unix domain socket with the appropriate type (SOCK_STREAM or SOCK_SEQPACKET) to match the vsock connection type

## References

- [VirtIO Specification v1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html)
- [GitHub Issue #4822](https://github.com/firecracker-microvm/firecracker/issues/4822)
- [Linux vsock(7) man page](https://man7.org/linux/man-pages/man7/vsock.7.html)

## Future Enhancements

Potential improvements for future consideration:

1. **Socket type mismatch detection**: Detect and report when host-side Unix socket type doesn't match vsock socket type
2. **Metrics**: Add metrics for SEQPACKET vs STREAM connection counts
3. **Configuration**: Allow configuration of default socket type per port
