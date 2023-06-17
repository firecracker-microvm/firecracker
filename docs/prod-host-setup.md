# Production Host Setup Recommendations

Firecracker relies on KVM and on the processor virtualization features for
workload isolation. The host and guest kernels and host microcode must be
regularly patched in accordance with your distribution's security advisories
such as [ALAS](https://alas.aws.amazon.com/alas2023.html) for Amazon Linux.

Security guarantees and defense in depth can only be upheld, if the following
list of recommendations are implemented in production.

## Firecracker Configuration

### Seccomp

Firecracker uses
[seccomp](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
filters to limit the system calls allowed by the host OS to the required
minimum.

By default, Firecracker uses the most restrictive filters, which is the
recommended option for production usage.

Production usage of the `--seccomp-filter` or `--no-seccomp` parameters is not
recommended.

### 8250 Serial Device

Firecracker implements the 8250 serial device, which is visible from the guest
side and is tied to the Firecracker/non-daemonized jailer process stdout.
Without proper handling, because the guest has access to the serial device,
this can lead to unbound memory or storage usage on the host side. Firecracker
does not offer users the option to limit serial data transfer, nor does it
impose any restrictions on stdout handling. Users are responsible for handling
the memory and storage usage of the Firecracker process stdout. We suggest
using any upper-bounded forms of storage, such as fixed-size or ring buffers,
using programs like `journald` or `logrotate`, or redirecting to `/dev/null`
or a named pipe. Furthermore, we do not recommend that users enable the serial
device in production. To disable it in the guest kernel, use the
`8250.nr_uarts=0` boot argument when configuring the boot source. Please be
aware that the device can be reactivated from within the guest even if it was
disabled at boot.

If Firecracker's `stdout` buffer is non-blocking and full (assuming it has a
bounded size), any subsequent writes will fail, resulting in data loss, until
the buffer is freed.

### Log files

Firecracker outputs logging data into a named pipe, socket, or file using the
path specified in the `log_path` field of logger configuration. Firecracker can
generate log data as a result of guest operations and therefore the guest can
influence the volume of data written in the logs. Users are responsible
for consuming and storing this data safely. We suggest using any upper-bounded
forms of storage, such as fixed-size or ring buffers, programs like `journald`
or `logrotate`, or redirecting to a named pipe.

### Logging and performance

We recommend adding `quiet loglevel=1` to the host kernel command line to limit
the number of messages written to the serial console. This is because some host
configurations can have an effect on Firecracker's performance as the process
will generate host kernel logs during normal operations.

The most recent example of this was the addition of `console=ttyAMA0` host
kernel command line argument on one of our testing setups. This enabled console
logging, which degraded the snapshot restore time from 3ms to 8.5ms on
`aarch64`. In this case, creating the tap device for snapshot restore
generated host kernel logs, which were very slow to write.

### Logging and signal handlers

Firecracker installs custom signal handlers for some of the POSIX signals, such
as SIGSEGV, SIGSYS, etc.

The custom signal handlers used by Firecracker are not async-signal-safe, since
they write logs and flush the metrics, which use locks for synchronization.
While very unlikely, it is possible that the handler will intercept a signal on
a thread which is already holding a lock to the log or metrics buffer.
This can result in a deadlock, where the specific Firecracker thread becomes
unresponsive.

While there is no security impact caused by the deadlock, we recommend that
customers have an overwatcher process on the host, that periodically looks
for Firecracker processes that are unresponsive, and kills them, by SIGKILL.

## Jailer Configuration

For assuring secure isolation in production deployments, Firecracker should be
started using the `jailer` binary that's part of each Firecracker release, or
executed under process constraints equal or more restrictive than those in the jailer.
For more about Firecracker sandboxing please see
[Firecracker design](design.md)

The Jailer process applies
[cgroup](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt),
namespace isolation and drops privileges of the Firecracker process.

To set up the jailer correctly, you'll need to:

- Create a dedicated non-privileged POSIX user and group to run Firecracker
  under. Use the created POSIX user and group IDs in Jailer's ``--uid <uid>``
  and ``--gid <gid>`` flags, respectively. This will run the Firecracker as
  the created non-privileged user and group. All file system resources used for
  Firecracker should be owned by this user and group. Apply least privilege to
  the resource files owned by this user and group to prevent other accounts from
  unauthorized file access.
  When running multiple Firecracker instances it is recommended that each runs
  with its unique `uid` and `gid` to provide an extra layer of security for
  their individually owned resources in the unlikely case where any one of the
  jails is broken out of.

Firecracker's customers are strongly advised to use the provided
`resource-limits` and `cgroup` functionalities encapsulated within jailer,
in order to control Firecracker's resource consumption in a way that makes
the most sense to their specific workload. While aiming to provide as much
control as possible, we cannot enforce aggressive default constraints
resources such as memory or CPU because these are highly dependent on the
workload type and usecase.

Here are some recommendations on how to limit the process's resources:

### Disk

- `cgroup` provides a
  [Block IO Controller](https://www.kernel.org/doc/Documentation/cgroup-v1/blkio-controller.txt)
  which allows users to control I/O operations through the following files:
  - `blkio.throttle.io_serviced` - bounds the number of I/Os issued to disk
  - `blkio.throttle.io_service_bytes` - sets a limit on the number of bytes
    transferred to/from the disk

- Jailer's `resource-limit` provides control on the disk usage through:
  - `fsize` - limits the size in bytes for files created by the process
  - `no-file` - specifies a value greater than the maximum file
    descriptor number that can be opened by the process. If not specified,
    it defaults to 4096.

### Memory

- `cgroup` provides a
  [Memory Resource Controller](https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt)
  to allow setting upper limits to memory usage:
  - `memory.limit_in_bytes` - bounds the memory usage
  - `memory.memsw.limit_in_bytes` - limits the memory+swap usage
  - `memory.soft_limit_in_bytes` -  enables flexible sharing of memory. Under
    normal circumstances, control groups are allowed to use as much of the
    memory as needed, constrained only by their hard limits set with the
    `memory.limit_in_bytes` parameter. However, when the system detects
    memory contention or low memory, control groups are forced to restrict
    their consumption to their soft limits.

### vCPU

- `cgroup`’s
  [CPU Controller](https://www.kernel.org/doc/Documentation/cgroup-v1/cpuacct.txt)
  can guarantee a minimum number of CPU shares when a system is busy and
  provides CPU bandwidth control through:
  - `cpu.shares` - limits the amount of CPU that each group it is expected to
    get. The percentage of CPU assigned is the value of shares divided by the
    sum of all shares in all `cgroups` in the same level
  - `cpu.cfs_period_us` - bounds the duration in us of each scheduler period,
    for bandwidth decisions. This defaults to 100ms
  - `cpu.cfs_quota_us` - sets the maximum time in microseconds during each
    `cfs_period_us` for which the current group will be allowed to run
  - `cpuacct.usage_percpu` - limits the CPU time, in ns, consumed by the
    process in the group, separated by CPU

Additional details of Jailer features can be found in the
[Jailer documentation](jailer.md).

## Host Security Configuration

### Constrain CPU overhead caused by kvm-pit kernel threads

The current implementation results in host CPU usage increase on x86 CPUs when
a guest injects timer interrupts with the help of kvm-pit kernel thread.
kvm-pit kthread is by default part of the root cgroup.

To mitigate the CPU overhead we recommend two system level configurations.

1.
    Use an external agent to move the `kvm-pit/<pid of firecracker>` kernel
    thread in the microVM’s cgroup (e.g., created by the Jailer).
    This cannot be done by Firecracker since the thread is created by the Linux
    kernel after guest start, at which point Firecracker is de-privileged.
1.
    Configure the kvm limit to a lower value. This is a system-wide
    configuration available to users without Firecracker or Jailer changes.
    However, the same limit applies to APIC timer events, and users will need
    to test their workloads in order to apply this mitigation.

To modify the kvm limit for interrupts that can be injected in a second.

1. `sudo modprobe -r (kvm_intel|kvm_amd) kvm`
1. `sudo modprobe kvm min_timer_period_us={new_value}`
1. `sudo modprobe (kvm_intel|kvm_amd)`

To have this change persistent across boots we can append the option to
`/etc/modprobe.d/kvm.conf`:

`echo "options kvm min_timer_period_us=" >> /etc/modprobe.d/kvm.conf`

### Mitigating Network flooding issues

Network can be flooded by creating connections and sending/receiving a
significant amount of requests. This issue can be mitigated either by
configuring rate limiters for the network interface as explained within
[Network Interface documentation](api_requests/patch-network-interface.md),
or by using one of the tools presented below:

- `tc qdisc` - manipulate traffic control settings by configuring filters.

When traffic enters a classful qdisc, the filters are consulted and the
packet is enqueued into one of the classes within. Besides
containing other qdiscs, most classful qdiscs perform rate control.

- `netnamespace` and `iptables`
  - `--pid-owner` -  can be used to match packets based on the PID that was
    responsible for them
  - `connlimit` - restricts the number of connections for a destination IP
    address/from a source IP address, as well as limit the bandwidth

### Mitigating Noisy-Neighbour Storage Device Contention

Data written to storage devices is managed in Linux with a page cache.
Updates to these pages are written through to their mapped storage
devices asynchronously at the host operating system's discretion.
As a result, high storage output can result in this cache being
filled quickly resulting in a backlog which can slow down I/O of
other guests on the host.

To protect the resource access of the guests, make sure to tune each Firecracker
process via the following tools:

- [Jailer](jailer.md): A wrapper environment designed to contain Firecracker
                       and strictly control what the process and its guest has
                       access to. Take note of the
                       [jailer operations guide](jailer.md#jailer-operation),
                       paying particular note to the `--resource-limit` parameter.
- Rate limiting: Rate limiting functionality is supported for both networking
                 and storage devices and is configured by the operator of the
                 environment that launches the Firecracker process and its
                 associated guest.
                 See the [block device documentation](api_requests/patch-block.md)
                 for examples of calling the API to configure rate limiting.

### Disabling swapping to disk or enabling secure swap

Memory pressure on a host can cause memory to be written to drive storage when
swapping is enabled. Disabling swap mitigates data remanence issues related to
having guest memory contents on microVM storage devices.

Verify that swap is disabled by running:

```bash
grep -q "/dev" /proc/swaps && \
echo "swap partitions present (Recommendation: no swap)" \
|| echo "no swap partitions (OK)"
```

### Mitigating hardware vulnerabilities

> **Note** Firecracker is not able to mitigate host's hardware vulnerabilities.
Adequate mitigations need to be put in place when configuring the host.

> **Note** Firecracker is designed to provide isolation boundaries between
microVMs running in different Firecracker processes. It is strongly recommended
that each Firecracker process corresponds to a workload of a single tenant.

> **Note** For security and stability reasons it is highly recommended to load
updated microcode as soon as possible. Aside from keeping the system firmware
up-to-date, when the kernel is used to load updated microcode of the CPU this
should be done as early as possible in the boot process.

#### Side channel attacks

It is strongly recommended that users follow the
[Linux kernel documentation on hardware vulnerabilities](https://docs.kernel.org/admin-guide/hw-vuln/index.html)
when configuring mitigations against side channel attacks including "Spectre"
and "Meltdown" attacks
(see [Page Table Isolation](https://docs.kernel.org/arch/x86/pti.html)
and [Speculation Control](https://docs.kernel.org/userspace-api/spec_ctrl.html)).

Additionally users should consider disabling
[Kernel Samepage Merging](https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html)
to mitigate [side channel issues](https://eprint.iacr.org/2013/448.pdf)
relying on the page deduplication for revealing what memory pages are
accessed by another process.

##### Use memory with Rowhammer mitigation support

Rowhammer is a memory side-channel issue that can lead to unauthorized cross-
process memory changes.

Using DDR4 memory that supports Target Row Refresh (TRR) with error-correcting
code (ECC) is recommended. Use of pseudo target row refresh (pTRR) for systems
with pTRR-compliant DDR3 memory can help mitigate the issue, but it also
incurs a performance penalty.

##### Vendor-specific recommendations

For vendor-specific recommendations, please consult the resources below:

- Intel: [Software Security Guidance](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/overview.html)
- AMD: [AMD Product Security](https://www.amd.com/en/resources/product-security.html)
- ARM: [Speculative Processor Vulnerability](https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability)

##### [ARM only] Physical counter directly passed through to the guest

On ARM, the physical counter (i.e `CNTPCT`) it is returning the
[actual EL1 physical counter value of the host][1]. From the discussions before
merging this change [upstream][2], this seems like a conscious design decision
of the ARM code contributors, giving precedence to performance over the ability
to trap and control this in the hypervisor.

##### Verification

[spectre-meltdown-checker script](https://github.com/speed47/spectre-meltdown-checker)
can be used to assess host's resilience against several transient execution
CVEs and receive guidance on how to mitigate them.

The script is used in integration tests by the Firecracker team. It can be
downloaded and executed like:

```bash
# Read https://meltdown.ovh before running it.
wget -O - https://meltdown.ovh | bash
```

[1]: https://elixir.free-electrons.com/linux/v4.14.203/source/virt/kvm/arm/hyp/timer-sr.c#L63
[2]: https://lists.cs.columbia.edu/pipermail/kvmarm/2017-January/023323.html
