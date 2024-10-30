# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
A utility for sending a UDP message with UDP oflload enabled.

Inspired by the "TUN_F_CSUM is a must" chapter
in https://blog.cloudflare.com/fr-fr/virtual-networking-101-understanding-tap/
by Cloudflare.
"""

import socket
import sys


def eprint(*args, **kwargs):
    """Print to stderr"""
    print(*args, file=sys.stderr, **kwargs)


# Define SOL_UDP and UDP_SEGMENT if not defined in the system headers
try:
    from socket import SOL_UDP, UDP_SEGMENT
except ImportError:
    SOL_UDP = 17  # Protocol number for UDP
    UDP_SEGMENT = 103  # Option code for UDP segmentation (non-standard)


if __name__ == "__main__":
    # Get the IP and port from command-line arguments
    if len(sys.argv) != 3:
        eprint("Usage: python3 udp_offload.py <ip_address> <port>")
        sys.exit(1)

    ip_address = sys.argv[1]
    port = int(sys.argv[2])

    # Create a UDP socket
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set the UDP segmentation option (UDP_SEGMENT) to 1400 bytes
    OPTVAL = 1400
    try:
        sockfd.setsockopt(SOL_UDP, UDP_SEGMENT, OPTVAL)
    except (AttributeError, PermissionError):
        eprint("Unable to set UDP_SEGMENT option")
        sys.exit(1)

    # Set the destination address and port
    servaddr = (ip_address, port)

    # Send the message to the destination address
    MESSAGE = b"x"
    try:
        sockfd.sendto(MESSAGE, servaddr)
        print("Message sent successfully")
    except socket.error as e:
        eprint(f"Error sending message: {e}")
        sys.exit(1)

    sockfd.close()
