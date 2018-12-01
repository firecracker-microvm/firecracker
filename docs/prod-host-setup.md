# Production Host Setup Recommendations

## Jailer Configuration

Using Jailer in a production Firecracker deployment is highly recommended,
as it provides additional security boundaries for the microVM.
The Jailer process applies
[cgroup](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt),
namespace,
[seccomp](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
isolation and drops privileges of the Firecracker process.

To set up the jailer correctly, you'll need to:

- Create a dedicated non-privileged POSIX user and group to run Firecracker
  under. Use the created POSIX user and group IDs in Jailer's ``--uid <uid>``
  and ``--guid <gid>`` flags, respectively. This will run the Firecracker as
  the created non-privileged user and group. All file system resources used for
  Firecracker should be owned by this user and group. Apply least privilege to
  the resource files owned by this user and group to prevent other accounts from
  unauthorized file access.

- Use Jailer's ``--seccomp-level 2`` flag to enable seccomp filter. The Jailer
  will apply a restrictive filter on what ``syscall`` and associated call
  parameters can issued by Firecracker.

Additional details of Jailer features can be found in the
[Jailer documentation](jailer.md).

## Host Security Configuration

### Mitigating Side-Channel Issues

When deploying Firecracker microVMs to handle multi-tenant workloads, the
following host environment configurations are strongly recommended to guard
against side-channel security issues.

#### Disable Simultaneous Multithreading (SMT)

Disabling SMT will help mitigate side-channels issues between sibling
threads on the same physical core.

SMT can be disabled by adding the following Kernel boot parameter to the host:

```
nosmt=force
````

Verification can be done by running:

```bash
(grep -q "^forceoff$\|^notsupported$" /sys/devices/system/cpu/smt/control && echo "Hyperthreading: DISABLED") || echo "Hyperthreading: ENABLED"
```

#### Check Kernel Page-Table Isolation (KPTI) support

KPTI is used to prevent certain side-channel issues that allow access to
protected kernel memory pages that are normally inaccessible to guests. Some
variants of Meltdown can be mitigated by enabling this feature.

Verification can be done by running:

```bash
(grep -q "^Mitigation: PTI$" /sys/devices/system/cpu/vulnerabilities/meltdown && echo "KPTI: SUPPORTED") || echo "KPTI: NOT SUPPORTED"
```

#### Disable Kernel Same-page Merging (KSM)

Disabling KSM mitigates side-channel issues which rely on de-duplication to
reveal what memory line was accessed by another process.

KSM can be disabled by executing the following as root:

```
echo "0" > /sys/kernel/mm/ksm/run
```

Verification can be done by running:

```bash
(grep -q "^0$" /sys/kernel/mm/ksm/run && echo "KSM: DISABLED") || echo "KSM: ENABLED"
```

#### Check for speculative branch prediction issue mitigation

Use a kernel compiled with retpoline and run on hardware with microcode
supporting Indirect Branch Prediction Barriers (IBPB) and Indirect Branch
Restricted Speculation (IBRS).

These features provide side-channel mitigation for variants of Spectre such
as the Branch Target Injection variant.

Verification can be done by running:

```bash
(grep -q "^Mitigation: Full generic retpoline, IBPB, IBRS_FW$" /sys/devices/system/cpu/vulnerabilities/spectre_v2 && echo "retpoline, IBPB, IBRS: ENABLED") || echo "retpoline, IBPB, IBRS: DISABLED"
```

#### Apply L1 Terminal Fault (L1TF) mitigation

These features provide mitigation for Foreshadow/L1TF side-channel issue on
affected hardware.

They can be enabled by adding the following Linux kernel boot parameter:

```
l1tf=full,force
```

which will also implicitly disable SMT.  This will apply the mitigation when
execution context switches into microVMs.

Verification can be done by running:

```bash
declare -a CONDITIONS=("Mitigation: PTE Inversion" "VMX: cache flushes")
for cond in "${CONDITIONS[@]}"; do (grep -q "$cond" /sys/devices/system/cpu/vulnerabilities/l1tf && echo "$cond: ENABLED") || echo "$cond: DISABLED"; done
```

#### Apply Speculative Store Bypass (SSBD) mitigation

This will mitigate variants of Spectre side-channel issues such as
Speculative Store Bypass and SpectreNG.

It can be enabled by adding the following Linux kernel boot parameter:

```
spec_store_bypass_disable=seccomp
```

which will apply SSB if seccomp is enabled by Firecracker's jailer.

Verification can be done by running:

```bash
cat /proc/*PID*/status | grep Speculation_Store_Bypass
```

where *PID* is the process ID being check.  Output shows one of the
following:

- not vulnerable
- thread mitigated
- thread force mitigated
- globally mitigated

#### Use memory with Rowhammer mitigation support

Rowhammer is a memory side-channel issue that can lead to unauthorized cross-
process memory changes.

Using DDR4 memory that supports Target Row Refresh (TRR) with error-correcting
code (ECC) is recommended. Use of pseudo target row refresh (pTRR) for systems
with pTRR-compliant DDR3 memory can help mitigate the issue, but it also
incurs a performance penalty.

#### Disable swapping to disk or enable secure swap

Memory pressure on a host can cause memory to be written to drive storage when
swapping is enabled. Disabling swap mitigates data remanence issues related to
having guest memory contents on microVM storage devices.

Verify that swap is disabled by running:

```bash
cat /proc/swaps
```

The output should not show any swap partition.
