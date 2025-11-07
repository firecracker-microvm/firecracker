# SEQPACKET Usage Guide for Firecracker vsock

## Overview

This guide demonstrates how to use SEQPACKET socket type with Firecracker's vsock implementation. SEQPACKET provides connection-oriented communication with message boundaries preserved, unlike STREAM sockets which treat data as a continuous byte stream.

## Use Cases for SEQPACKET

SEQPACKET is ideal when you need:
- **Message boundaries**: Each send/recv operation corresponds to a complete message
- **Datagram-like semantics**: With the reliability of connection-oriented sockets
- **Protocol framing**: Automatic message delineation without manual framing
- **VM-to-host communication**: Where discrete messages need to be preserved

Example scenarios:
- RPC systems where each request/response is a discrete message
- Event notification systems
- Command/control protocols
- Relaying datagrams over vsock while preserving boundaries

## Guest-Side Usage (Inside VM)

### Go Example

```go
package main

import (
    "fmt"
    "golang.org/x/sys/unix"
)

func main() {
    // Create a SEQPACKET vsock socket
    socketFd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_SEQPACKET, 0)
    if err != nil {
        panic(fmt.Sprintf("Failed to create socket: %v", err))
    }
    defer unix.Close(socketFd)

    // Connect to host (CID 2) on port 500
    sockaddr := &unix.SockaddrVM{
        CID:  2,    // Host CID
        Port: 500,  // Destination port
    }
    
    if err := unix.Connect(socketFd, sockaddr); err != nil {
        panic(fmt.Sprintf("Failed to connect: %v", err))
    }

    // Send a message (boundaries preserved)
    message := []byte("Hello from guest!")
    n, err := unix.Send(socketFd, message, 0)
    if err != nil {
        panic(fmt.Sprintf("Failed to send: %v", err))
    }
    fmt.Printf("Sent %d bytes\n", n)

    // Receive a message (complete message received in one call)
    buf := make([]byte, 4096)
    n, err = unix.Recv(socketFd, buf, 0)
    if err != nil {
        panic(fmt.Sprintf("Failed to receive: %v", err))
    }
    fmt.Printf("Received %d bytes: %s\n", n, string(buf[:n]))
}
```

### C Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

int main() {
    int sockfd;
    struct sockaddr_vm addr;
    char message[] = "Hello from guest!";
    char buffer[4096];
    ssize_t n;

    // Create SEQPACKET vsock socket
    sockfd = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // Connect to host (CID 2) on port 500
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HOST;  // 2
    addr.svm_port = 500;

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(1);
    }

    // Send message (boundaries preserved)
    n = send(sockfd, message, strlen(message), 0);
    if (n < 0) {
        perror("send");
        close(sockfd);
        exit(1);
    }
    printf("Sent %zd bytes\n", n);

    // Receive message (complete message in one call)
    n = recv(sockfd, buffer, sizeof(buffer), 0);
    if (n < 0) {
        perror("recv");
        close(sockfd);
        exit(1);
    }
    buffer[n] = '\0';
    printf("Received %zd bytes: %s\n", n, buffer);

    close(sockfd);
    return 0;
}
```

### Python Example

```python
import socket

# Create SEQPACKET vsock socket
sock = socket.socket(socket.AF_VSOCK, socket.SOCK_SEQPACKET)

try:
    # Connect to host (CID 2) on port 500
    sock.connect((2, 500))
    
    # Send message (boundaries preserved)
    message = b"Hello from guest!"
    sock.send(message)
    print(f"Sent {len(message)} bytes")
    
    # Receive message (complete message in one call)
    data = sock.recv(4096)
    print(f"Received {len(data)} bytes: {data.decode()}")
    
finally:
    sock.close()
```

## Host-Side Usage

### Setting up the vsock device

When starting Firecracker, configure the vsock device:

```bash
# Create the vsock socket path
VSOCK_PATH="/tmp/firecracker.vsock"

# Configure vsock via API
curl -X PUT 'http://localhost/vsock' \
  -H 'Content-Type: application/json' \
  -d '{
    "guest_cid": 3,
    "uds_path": "'${VSOCK_PATH}'"
  }'
```

### Connecting from Host with SEQPACKET

#### Using socat

```bash
# Connect to guest port 500 with SEQPACKET
echo "connect 500 seqpacket" | socat - UNIX-CONNECT:/tmp/firecracker.vsock

# For STREAM (default, backward compatible):
echo "connect 500" | socat - UNIX-CONNECT:/tmp/firecracker.vsock
# or explicitly:
echo "connect 500 stream" | socat - UNIX-CONNECT:/tmp/firecracker.vsock
```

#### Using nc (netcat) with Unix sockets

```bash
# Connect with SEQPACKET
echo "connect 500 seqpacket" | nc -U /tmp/firecracker.vsock
```

#### Python Script (Host-Side)

```python
#!/usr/bin/env python3
import socket
import os

def connect_to_guest_seqpacket(vsock_path, guest_port):
    """Connect to guest vsock with SEQPACKET socket type"""
    
    # Create Unix domain socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        # Connect to Firecracker's vsock Unix socket
        sock.connect(vsock_path)
        
        # Send connection request with SEQPACKET type
        connect_cmd = f"connect {guest_port} seqpacket\n"
        sock.send(connect_cmd.encode())
        
        # Read acknowledgment
        response = sock.recv(1024).decode().strip()
        if not response.startswith("OK"):
            raise Exception(f"Connection failed: {response}")
        
        print(f"Connected to guest port {guest_port} with SEQPACKET")
        
        # Now you can send/receive messages with preserved boundaries
        # Note: The underlying Unix socket is now SOCK_SEQPACKET
        
        # Send a message
        message = b"Hello from host!"
        sock.send(message)
        print(f"Sent {len(message)} bytes")
        
        # Receive response
        data = sock.recv(4096)
        print(f"Received {len(data)} bytes: {data.decode()}")
        
    finally:
        sock.close()

if __name__ == "__main__":
    vsock_path = "/tmp/firecracker.vsock"
    guest_port = 500
    connect_to_guest_seqpacket(vsock_path, guest_port)
```

#### Go Script (Host-Side)

```go
package main

import (
    "fmt"
    "net"
    "strings"
)

func connectToGuestSeqpacket(vsockPath string, guestPort int) error {
    // Connect to Firecracker's vsock Unix socket
    conn, err := net.Dial("unix", vsockPath)
    if err != nil {
        return fmt.Errorf("failed to connect: %w", err)
    }
    defer conn.Close()

    // Send connection request with SEQPACKET type
    connectCmd := fmt.Sprintf("connect %d seqpacket\n", guestPort)
    _, err = conn.Write([]byte(connectCmd))
    if err != nil {
        return fmt.Errorf("failed to send connect command: %w", err)
    }

    // Read acknowledgment
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return fmt.Errorf("failed to read response: %w", err)
    }

    response := strings.TrimSpace(string(buf[:n]))
    if !strings.HasPrefix(response, "OK") {
        return fmt.Errorf("connection failed: %s", response)
    }

    fmt.Printf("Connected to guest port %d with SEQPACKET\n", guestPort)

    // Send a message
    message := []byte("Hello from host!")
    _, err = conn.Write(message)
    if err != nil {
        return fmt.Errorf("failed to send message: %w", err)
    }
    fmt.Printf("Sent %d bytes\n", len(message))

    // Receive response
    n, err = conn.Read(buf)
    if err != nil {
        return fmt.Errorf("failed to receive: %w", err)
    }
    fmt.Printf("Received %d bytes: %s\n", n, string(buf[:n]))

    return nil
}

func main() {
    vsockPath := "/tmp/firecracker.vsock"
    guestPort := 500

    if err := connectToGuestSeqpacket(vsockPath, guestPort); err != nil {
        panic(err)
    }
}
```

## Key Differences: STREAM vs SEQPACKET

### STREAM Socket Behavior

```python
# Sender
sock.send(b"Message1")
sock.send(b"Message2")

# Receiver might get:
data = sock.recv(4096)  # Could be "Message1Message2" or "Message1Mes" or any combination
```

### SEQPACKET Socket Behavior

```python
# Sender
sock.send(b"Message1")
sock.send(b"Message2")

# Receiver gets:
data1 = sock.recv(4096)  # Always gets exactly "Message1"
data2 = sock.recv(4096)  # Always gets exactly "Message2"
```

## Message Boundary Preservation Example

### Guest Application (Python)

```python
import socket
import time

sock = socket.socket(socket.AF_VSOCK, socket.SOCK_SEQPACKET)
sock.connect((2, 500))

# Send multiple discrete messages
messages = [
    b"Command: START",
    b"Command: PROCESS",
    b"Command: STOP"
]

for msg in messages:
    sock.send(msg)
    time.sleep(0.1)  # Small delay between messages

# Each message is received as a complete unit on the host side
sock.close()
```

### Host Application (Python)

```python
import socket

# ... connection setup code ...

# Receive messages - each recv() gets exactly one complete message
while True:
    try:
        data = sock.recv(4096)
        if not data:
            break
        print(f"Received complete message: {data.decode()}")
        # Output:
        # Received complete message: Command: START
        # Received complete message: Command: PROCESS
        # Received complete message: Command: STOP
    except Exception as e:
        print(f"Error: {e}")
        break
```

## Testing SEQPACKET Support

### Verify Feature is Available

From inside the guest VM:

```bash
# Check if SEQPACKET feature is negotiated
cat /sys/devices/virtual/virtio-ports/vport*/features
# Should show bit 0 set (VIRTIO_VSOCK_F_SEQPACKET)
```

### Simple Test Script

```bash
#!/bin/bash
# test_seqpacket.sh

VSOCK_PATH="/tmp/firecracker.vsock"
GUEST_PORT=9999

# Start a listener in the guest (run this in guest VM first)
# python3 -c "
# import socket
# s = socket.socket(socket.AF_VSOCK, socket.SOCK_SEQPACKET)
# s.bind((socket.VMADDR_CID_ANY, 9999))
# s.listen(1)
# conn, addr = s.accept()
# print(f'Connected: {addr}')
# while True:
#     data = conn.recv(1024)
#     if not data: break
#     print(f'Received: {data}')
#     conn.send(b'ACK: ' + data)
# "

# Connect from host with SEQPACKET
(
    echo "connect ${GUEST_PORT} seqpacket"
    sleep 0.5
    echo "Test message 1"
    sleep 0.5
    echo "Test message 2"
    sleep 0.5
) | socat - UNIX-CONNECT:${VSOCK_PATH}
```

## Troubleshooting

### Connection Refused

If you get connection refused:
1. Ensure the guest application is listening on the specified port
2. Verify the vsock device is properly configured
3. Check that the guest CID matches your configuration

### Socket Type Mismatch

If the host tries to connect with SEQPACKET but the guest is listening with STREAM (or vice versa), the connection will be refused. Ensure both sides use the same socket type.

### Feature Not Available

If SEQPACKET is not working:
1. Verify you're using a recent version of Firecracker with SEQPACKET support
2. Check that the guest kernel supports vsock SEQPACKET (Linux 5.6+)
3. Ensure the VIRTIO_VSOCK_F_SEQPACKET feature is negotiated

## Performance Considerations

- **SEQPACKET**: Slightly higher overhead due to message boundary tracking
- **STREAM**: Lower overhead, but requires manual framing for message boundaries
- **Use SEQPACKET when**: Message boundaries are important and worth the small overhead
- **Use STREAM when**: You're streaming continuous data without discrete messages

## References

- VirtIO vsock specification: https://docs.oasis-open.org/virtio/virtio/v1.2/
- Linux vsock documentation: https://www.kernel.org/doc/html/latest/networking/af_vsock.html
- Firecracker vsock documentation: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
