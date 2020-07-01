# Firecracker Design

## Scope

### What is Firecracker

Firecracker is a new virtualization technology that enables customers to deploy
lightweight *micro* Virtual Machines or microVMs. Firecracker microVMs combine
the security and workload isolation properties of traditional VMs with the
speed, agility and resource efficiency enabled by containers. They provide a
secure, trusted environment for multi-tenant services, while maintaining
minimal overhead.

The scope of this document is to describe the features and architecture of the
Firecracker virtual machine manager (VMM).

### Features

1. Firecracker can safely run workloads from different customers on the same
   machine.
1. Customers can create microVMs with any combination of vCPU and memory to
   match their application requirements.
1. Firecracker microVMs can oversubscribe host CPU and memory. The degree of
   oversubscription is controlled by customers, who may factor in workload
   correlation and load in order to ensure smooth host system operation.
1. With a microVM configured with a minimal Linux kernel, single-core CPU, and
   128 MiB of RAM, Firecracker supports a steady mutation rate of 5 microVMs
   per host core per second (e.g., one can create 180 microVMs per second on a
   host with 36 physical cores).
1. The number of Firecracker microVMs running simultaneously on a host is
   limited only by the availability of hardware resources.
1. Each microVM exposes a host-facing API via an in-process HTTP server.
1. Each microVM provides guest-facing access to host-configured metadata via
   the `/mmds` API.

### Specifications

Firecracker's technical specifications are available in the
[Specifications document](../SPECIFICATION.md).

## Host Integration

The following diagram depicts an example host running Firecracker microVMs.

![Firecracker Host Integration](
images/firecracker_host_integration.png?raw=true
"Firecracker Host Integration")

Firecracker runs on Linux hosts with 4.14 or newer kernels and with Linux
guest OSs (from this point on, referred to as guests). In production
environments, Firecracker should be started only via the `jailer` binary.
The `firecracker` binary can also be executed directly, but this will no longer
be possible in the future. After launching the process, users interact with
the Firecracker API to configure the microVM, before issuing the
`InstanceStart` command.

### Host Networking Integration

Firecracker emulated network devices are backed by TAP devices on the host. To
make use of Firecracker, we expect our customers to leverage on-host networking
solutions.

### Storage

Firecracker emulated block devices are backed by files on the host. To be able
to mount block devices in the guest, the backing files need to be pre-formatted
with a filesystem that the guest kernel supports.

## Internal Architecture

Each Firecracker process encapsulates one and only one microVM. The process
runs the following threads: API, VMM and vCPU(s). The API thread is responsible
for Firecracker's API server and associated control plane. It's never in the
fast path of the virtual machine. The VMM thread exposes the machine model,
minimal legacy device model, microVM metadata service (MMDS) and VirtIO device
emulated Net, Block and Vsock devices, complete with I/O rate limiting. In
addition to them, there are one or more vCPU threads (one per guest CPU core).
They are created via KVM and run the `KVM_RUN` main loop. They execute
synchronous I/O and memory-mapped I/O operations on devices models.

### Threat Containment

From a security perspective, all vCPU threads are considered to be running
malicious code as soon as they have been started; these malicious threads need
to be contained. Containment is achieved by nesting several trust zones which
increment from least trusted or least safe (guest vCPU threads) to most trusted
or safest (host). These trusted zones are separated by barriers that enforce
aspects of Firecracker security. For example, all outbound network traffic data
is copied by the Firecracker I/O thread from the emulated network interface to
the backing host TAP device, and I/O rate limiting is applied at this point.
These barriers are marked in the diagram below.

![Firecracker Threat Containment](
images/firecracker_threat_containment.png?raw=true
"Firecracker Threat Containment")

## Components and Features

### Machine Model

#### Layout

Firecracker provides guests with storage and network access via emulated VirtIO
Net and VirtIO Block devices. It also exposes a serial console and partial
keyboard controller, the latter being used by guests to reset the VM (either
soft or hard reset). Within Firecracker, the purpose of the I8042 device is to
signal the microVM that the guest has requested a reboot.

In addition to the Firecracker provided device models, guests also see the
Programmable Interrupt Controllers (PICs), the I/O Advanced Programmable
Interrupt Controller (IOAPIC), and the Programmable Interval Timer (PIT) that
KVM supports.

#### Exposing the CPU to the guest

Firecracker allows the exposure of either the host processor information or any
other family/model/stepping as a way to keep compatibility for services that
were not running on top of it. In addition, Firecracker supports feature
masking via CPUID. To simplify customer operation, CPU feature templates can be
set via the Firecracker API. Currently, the available feature templates to
choose from are EC2 C3 and EC2 T2 instance types.

#### Clocksources available to guests

Firecracker only exposes kvm-clock to customers.

### I/O: Storage, Networking and Rate Limiting

Firecracker provides VirtIO/block and VirtIO/net emulated devices, along with
the application of rate limiters to each volume and network interface to make
sure host hardware resources are used fairly by multiple microVMs. These are
implemented using a token bucket algorithm based on two buckets. One is
associated with the number of operations per second and the other one with the
bandwidth. The customer can create and configure rate limiters via the API by
specifying token bucket configurations for ingress and egress. Each token
bucket is defined via the bucket size, I/O cost, refill rate, maximum burst,
and initial value. This enables the customer to define flexible rate limiters
that support bursts or specific bandwidth/operations limitations.

### MicroVM Metadata Service

Firecracker microVMs expose access to a minimal MicroVM-Metadata Service
(MMDS) to the guest through the API endpoint. The metadata stored by the
service is fully configured by users.

### Jailing

The Firecracker process can be started by another `jailer` process. The jailer
sets up system resources that require elevated permissions (e.g., cgroup,
chroot), drops privileges, and then exec()s into the Firecracker binary, which
then runs as an unprivileged process. Past this point, Firecracker can only
access resources that a privileged third-party grants access to (e.g., by
copying a file into the chroot, or passing a file descriptor).

Seccomp filters are used to further limit the system calls Firecracker can use.
There are 3 possible levels of seccomp filtering, configurable by passing a
command line argument to the jailer: 0 (disabled), 1 (whitelists a set of
trusted system calls by their identifiers) and 2 (whitelists a set of trusted
system calls with trusted parameter values), the latter being the most
restrictive and the recommended one. The filters are loaded in the Firecracker
process, immediately before the execution of the untrusted guest code starts.

#### Cgroups and Quotas

Each Firecracker microVM is further encapsulated into a cgroup. By setting the
affinity of the Firecracker microVM to a node via the cpuset subsystem, one
can prevent the migration of said microVM from one node to another, something
that would impair performance and cause unnecessary contention on shared
resources. In addition to setting the affinity, each Firecracker microVM can
have its own dedicated quota of the CPU time via the cpu subsystem, thus
guaranteeing that resources are fairly shared across Firecracker microVMs.

### Monitoring

Firecracker emits logs and metric counters, each on a named pipe that is passed
via the API. Logs are flushed line by line, whereas metrics are emitted when the
instance starts, then every 60 seconds while it's running, and on panic.
Firecracker customers are responsible for collecting data in the Firecracker
log files. In production builds, Firecracker does not expose the serial console
port, since it may contain guest data that the host should not see.
