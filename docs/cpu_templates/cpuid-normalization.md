# CPUID normalization (x86_64 only)

On x86_64, Firecracker makes certain modifications to the guest's CPUID
regardless of whether a CPU template is used. This is referred to as
`CPUID normalization`. If a CPU template is used the normalization is
performed _after_ the CPU template is applied. That means that if the CPU
template configures CPUID bits used in the normalization process, they will
be overwritten.

See also: [boot protocol settings](boot-protocol.md)

## x86_64 common CPUID normalization

| Description                                                                          | Leaf       | Subleaf | Register      | Bits  |
|--------------------------------------------------------------------------------------|:----------:|:-------:|:-------------:|:-----:|
| Pass through vendor ID from host                                                     | 0x0        | -       | EBX, ECX, EDX | all   |
| Set CLFLUSH line size                                                                | 0x1        | -       | EBX           | 15:8  |
| Set maximum number of addressable IDs for logical processors in the physical package | 0x1        | -       | EBX           | 23:16 |
| Set initial APIC ID                                                                  | 0x1        | -       | EBX           | 31:24 |
| Disable PDCM (Perfmon and Debug Capability)                                          | 0x1        | -       | ECX           | 15    |
| Enable TSC_DEADLINE                                                                  | 0x1        | -       | ECX           | 24    |
| Enable HYPERVISOR                                                                    | 0x1        | -       | ECX           | 31    |
| Set HTT value if the microVM's CPU count is greater than 1                           | 0x1        | -       | EDX           | 28    |
| Insert leaf 0xb, subleaf 0x1 filled with `0` if it is not already present            | 0xb        | 0x1     | all           | all   |
| Update extended topology enumeration                                                 | 0xb        | all     | EAX           | 4:0   |
| Update extended topology enumeration                                                 | 0xb        | all     | EBX           | 15:0  |
| Update extended topology enumeration                                                 | 0xb        | all     | ECX           | 15:8  |
| Pass through L1 cache and TLB information from host                                  | 0x80000005 | -       | all           | all   |
| Pass through L2 cache and TLB and L3 cache information from host                     | 0x80000006 | -       | all           | all   |

## Intel-specific CPUID normalization

| Description                                                    | Leaf                               | Subleaf | Register           | Bits  |
|----------------------------------------------------------------|:----------------------------------:|:-------:|:------------------:|:-----:|
| Update deterministic cache parameters                          | 0x4                                | all     | EAX                | 31:14 |
| Disable Intel Turbo Boost technology                           | 0x6                                | -       | EAX                | 1     |
| Disable frequency selection                                    | 0x6                                | -       | ECX                | 3     |
| Set FDP_EXCPTN_ONLY bit                                        | 0x7                                | 0x0     | EBX                | 6     |
| Set "Deprecates FPU CS and FPU DS values" bit                  | 0x7                                | 0x0     | EBX                | 13    |
| Disable performance monitoring                                 | 0xa                                | -       | EAX, EBX, ECX, EDX | all   |
| Update brand string to use a default format and real frequency | 0x80000002, 0x80000003, 0x80000004 | -       | EAX, EBX, ECX, EDX | all   |

## AMD-specifc CPUID normalization

| Description                                          | Leaf                               | Subleaf | Register           | Bits  |
|------------------------------------------------------|:----------------------------------:|:-------:|:------------------:|:-----:|
| Set IA32_ARCH_CAPABILITIES MSR as not present        | 0x7                                | -       | EDX                | 29    |
| Update largest extended function entry to 0x8000001f | 0x80000000                         | -       | EAX                | 31:0  |
| Set topology extension bit                           | 0x80000001                         | -       | ECX                | 22    |
| Update brand string with a default AMD value         | 0x80000002, 0x80000003, 0x80000004 | -       | EAX, EBX, ECX, EDX | all   |
| Update number of physical threads                    | 0x80000008                         | -       | ECX                | 7:0   |
| Update APIC ID size                                  | 0x80000008                         | -       | ECX                | 15:12 |
| Update cache topology information                    | 0x8000001d                         | all     | all                | all   |
| Update extended APIC ID                              | 0x8000001e                         | -       | EAX, EBX, ECX      | all   |
