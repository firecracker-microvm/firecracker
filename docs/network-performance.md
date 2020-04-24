# Firecracker network performance numbers

This document provides details about Firecracker network performance.
The numbers presented are dependent on the hardware (CPU, networking card, etc.), OS version and settings.
Scope of the measurements is to illustrate the limits for the emulation thread.

## TCP Throughput

Segment size/ Direction | 1460bytes | 256bytes | 128bytes | 96bytes
--- | --- | --- | --- |---
Ingress| 25Gbps | 23Gbps | 20Gbps | 18Gbps
Egress | 25Gbps | 23Gbps | 20Gbps | 18Gbps
Bidirectional | 18Gbps | 18Gbps | 18Gbps | 18Gbps

### Setup and test description

Throughput measurements were done using [iperf3](https://iperf.fr/). The target is to fully saturate the emulation thread and keep it at 100% utilization.
No adjustments were done to socket buffer, or any other network related kernel parameters.

To identify the limit of emulation thread, TCP throughput was measured between host and guest. An EC2 [M5d.metal](https://aws.amazon.com/ec2/instance-types/m5/) instance, running [Amazon Linux 2](https://aws.amazon.com/amazon-linux-ami/), was used as a host.

For ingress or egress throughput measurements, a Firecracker microVM running Kernel 4.14 with 4GB of Ram, 8 vCPUs and one network interface was used.
The measurements were taken using 6 iperf3 clients running on host and 6 iperf3 serves running on guest and vice versa.

For bidirectional throughput measurements, a Firecracker microVM running Amazon Linux 2, Kernel 4.14 with 4GB of Ram, 12 vCPUs and one network interface was used.
The measurements were taken using 4 iperf3 clients and 4 iperf3 servers running on both host and guest.

## Latency

The virtualization layer, Firecracker emulation thread plus host kernel stack, is responsible for adding on average 0.06ms of network latency.

### Setup and test description

Latency measurements were done using ping round trip times.
2 x EC2 M5d.metal instances running Amazon Linux 2 within the same [VPC](https://aws.amazon.com/vpc/) were used, with a security group configured so that it would allow traffic from instances using private IPs. A 10Mbps background traffic was running between instances.

Round trip time between instances was measured.

```rtt min/avg/max/mdev = 0.101/0.198/0.237/0.044 ms```

On one of the instances, a Firecracker microVM running Kernel 4.14, with 1 GB of RAM, 2 vCPUs, one network interface running was used.
Round trip between the microVM and the other instance was measured, while a 10Mbps background traffic was running.

```rtt min/avg/max/mdev = 0.191/0.321/0.519/0.058  ms```

From the difference between those we can conclude that ~0.06ms are the virtualization overhead.
