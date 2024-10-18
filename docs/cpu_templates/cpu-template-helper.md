# CPU template helper tool

The `cpu-template-helper` tool is a program designed to assist users with
creating and managing their custom CPU templates.

## Usage

The `cpu-template-helper` tool has two sets of commands: template-related
commands and fingerprint-related commands.

### Template-related commands

#### Dump command

This command dumps guest CPU configuration in the custom CPU template JSON
format.

```
cpu-template-helper template dump \
    --output <cpu-config> \
    [--template <cpu-template>] \
    [--config <firecracker-config>]
```

Users can utilize this as an entry point of a custom CPU template creation to
comprehend what CPU configuration are exposed to guests.

The guest CPU configuration consists of the following entities:

- x86_64
  - CPUID
  - MSRs (Model Specific Registers)
- aarch64
  - ARM registers

It retrieves the above entities exposed to a guest by applying the same preboot
process as Firecacker and capturing them in the state just before booting a
guest. More details about the preboot process can be found
[here](boot-protocol.md) and [here](cpuid-normalization.md).

> **Note** Some MSRs and ARM registers are not included in the output, since
> they are not reasonable to modify with CPU templates. The full list of them
> can be found in [Appendix](#appendix).

> **Note** Since the output depends on underlying hardware and software stack
> (BIOS, CPU, kernel, Firecracker), it is required to dump guest CPU
> configuration on each combination when creating a custom CPU template
> targetting them all.

#### Strip command

This command strips identical entries from multiple guest CPU configuration
files generated with the dump command.

```
cpu-template-helper template strip \
    --paths <cpu-config-1> <cpu-config-2> [..<cpu-config-N>] \
    --suffix <suffix>
```

One practical use case of the CPU template feature is to provide a consistent
CPU feature set to guests running on multiple CPU models. When creating a custom
CPU template for this purpose, it is efficient to focus on the differences in
guest CPU configurations across those CPU models. Given that a dumped guest CPU
configuration typically amounts to approximately 1,000 lines, this command
considerably narrows down the scope to consider.

#### Verify command

This command verifies that the given custom CPU template is applied correctly.

```
cpu-template-helper template verify \
    --template <cpu-template> \
    [--config <firecracker-config>]
```

Firecracker modifies the guest CPU configuration after the CPU template is
applied. Occasionally, due to hardware and/or software limitations, KVM might
not set the given configuration. Since Firecracker does not check them at
runtime, it is required to ensure that these situations don't happen with their
custom CPU templates before deploying it.

When a template is specified both through `--template` and in Firecracker
configuration file provided via `--config`, the template specified with
`--template` takes precedence.

> **Note** This command does not ensure that the contents of the template are
> sensible. Thus, users need to make sure that the template does not have any
> inconsistent entries and does not crash guests.

### Fingerprint-related commands

#### Dump command

This command not only dumps the guest CPU configuration, but also host
information that could affect the validity of custom CPU templates.

```
cpu-template-helper fingerprint dump \
    --output <output-path> \
    [--template <cpu-template>] \
    [--config <firecracker-config>]
```

Keeping the underlying hardware and software stack updated is essential for
maintaining security and leveraging new technologies. On the other hand, since
the guest CPU configuration can vary depending on the infrastructure, updating
it could lead to a situation where a custom CPU template loses its validity. In
addition, even if values of the guest CPU configuration don't change, its
internal behavior or semantics could still change. For instance, a kernel
version update may introduce changes to KVM emulation and a microcode update may
alter the behavior of CPU instructions.

To ensure awareness of these changes, it is strongly recommended to store the
fingerprint file at the time of creating a custom CPU template and to
continuously compare it with the current one.

#### Compare command

This command compares two fingerprint files: one was taken at the time of custom
CPU template creation and the other is taken currently.

```
cpu-template-helper fingerprint compare \
    --prev <prev-fingerprint> \
    --curr <curr-fingerprint> \
    --filters <field-1> [..<field-N>]
```

By continously comparing fingerprint files, users can ensure they are aware of
any changes that could require revising the custom CPU template. However, it is
worth noting that not all of these changes necessarily require a revision, and
some changes could be inconsequential to the custom CPU template depending on
its use case. To provide users with flexibility in comparing fingerprint files
based on situations or use cases, the `--filters` option allows users to select
which fields to compare.

As examples of when to compare fingerprint files:

- When bumping the Firecracker version up
- When bumping the kernel version up
- When applying a microcode update (or launching a new host (e.g. AWS EC2 metal
  instance))

## Sample scenario

This section gives steps of creating and managing a custom CPU template in a
sample scenario where the template is designed to provide a consistent set of
CPU features to a heterogeneous fleet consisting of multiple CPU models.

### Custom CPU template creation

1. Run the `cpu-template-helper template dump` command on each CPU model to
   retrieve guest CPU configuration.
1. Run the `cpu-template-helper template strip` command to remove identical
   entries across the dumped guest CPU configuration files.
1. Examine the differences of guest CPU configuration in details, determine
   which CPU features should be presented to guests and draft a custom CPU
   template.
1. Run the `cpu-template-helper template verify` command to check the created
   custom CPU template is applied correctly.
1. Conduct thorough testing of the template as needed to ensure that it does not
   contain any inconsistent entries and does not lead to guest crashes.

### Custom CPU template management

1. Run the `cpu-template-helper fingerprint dump` command on each CPU model at
   the same time when creating a custom CPU template.
1. Store the dumped fingerprint files together with the custom CPU template.
1. Run the `cpu-template-helper fingerprint dump` command to ensure the
   template's validity whenever you expect changes to the underlying hardware
   and software stack.
1. Run the `cpu-template-helper fingerprint compare` command to identify changes
   of the underlying environment introduced after creating the template.
1. (if changes are detected) Review the identified changes, make necessary
   revisions to the CPU template, and replace the fingerprint file with the new
   one.

> **Note** It is recommended to review the update process of the underlying
> stack on your infrastructure. This can help identify points that may require
> the above validation check.

## Appendix

### MSRs excluded from guest CPU configuration dump

| Register name                           | Index                   |
| --------------------------------------- | ----------------------- |
| MSR_IA32_TSC                            | 0x00000010              |
| MSR_ARCH_PERFMON_PERFCTRn               | 0x000000c1 - 0x000000d2 |
| MSR_ARCH_PERFMON_EVENTSELn              | 0x00000186 - 0x00000197 |
| MSR_ARCH_PERFMON_FIXED_CTRn             | 0x00000309 - 0x0000030b |
| MSR_CORE_PERF_FIXED_CTR_CTRL            | 0x0000038d              |
| MSR_CORE_PERF_GLOBAL_STATUS             | 0x0000038e              |
| MSR_CORE_PERF_GLOBAL_CTRL               | 0x0000038f              |
| MSR_CORE_PERF_GLOBAL_OVF_CTRL           | 0x00000390              |
| MSR_K7_EVNTSELn                         | 0xc0010000 - 0xc0010003 |
| MSR_K7_PERFCTR0                         | 0xc0010004 - 0xc0010007 |
| MSR_F15H_PERF_CTLn + MSR_F15H_PERF_CTRn | 0xc0010200 - 0xc001020c |
| MSR_IA32_VMX_BASIC                      | 0x00000480              |
| MSR_IA32_VMX_PINBASED_CTLS              | 0x00000481              |
| MSR_IA32_VMX_PROCBASED_CTLS             | 0x00000482              |
| MSR_IA32_VMX_EXIT_CTLS                  | 0x00000483              |
| MSR_IA32_VMX_ENTRY_CTLS                 | 0x00000484              |
| MSR_IA32_VMX_MISC                       | 0x00000485              |
| MSR_IA32_VMX_CR0_FIXEDn                 | 0x00000486 - 0x00000487 |
| MSR_IA32_VMX_CR4_FIXEDn                 | 0x00000488 - 0x00000489 |
| MSR_IA32_VMX_VMCS_ENUM                  | 0x0000048a              |
| MSR_IA32_VMX_PROCBASED_CTLS2            | 0x0000048b              |
| MSR_IA32_VMX_EPT_VPID_CAP               | 0x0000048c              |
| MSR_IA32_VMX_TRUE_PINBASED_CTLS         | 0x0000048d              |
| MSR_IA32_VMX_TRUE_PROCBASED_CTLS        | 0x0000048e              |
| MSR_IA32_VMX_TRUE_EXIT_CTLS             | 0x0000048f              |
| MSR_IA32_VMX_TRUE_ENTRY_CTLS            | 0x00000490              |
| MSR_IA32_VMX_VMFUNC                     | 0x00000491              |
| MSR_IA32_MCG_STATUS                     | 0x0000017a              |
| MSR_IA32_MCG_CTL                        | 0x0000017b              |
| MSR_IA32_MCG_EXT_CTL                    | 0x000004d0              |
| HV_X64_MSR_GUEST_OS_ID                  | 0x40000000              |
| HV_X64_MSR_HYPERCALL                    | 0x40000001              |
| HV_X64_MSR_VP_INDEX                     | 0x40000002              |
| HV_X64_MSR_RESET                        | 0x40000003              |
| HV_X64_MSR_VP_RUNTIME                   | 0x40000010              |
| HV_X64_MSR_VP_ASSIST_PAGE               | 0x40000073              |
| HV_X64_MSR_SCONTROL                     | 0x40000080              |
| HV_X64_MSR_STIMER0_CONFIG               | 0x400000b0              |
| HV_X64_MSR_CRASH_Pn                     | 0x40000100 - 0x40000104 |
| HV_X64_MSR_CRASH_CTL                    | 0x40000105              |
| HV_X64_MSR_REENLIGHTENMENT_CONTROL      | 0x40000106              |
| HV_X64_MSR_TSC_EMULATION_CONTROL        | 0x40000107              |
| HV_X64_MSR_TSC_EMULATION_STATUS         | 0x40000108              |
| HV_X64_MSR_SYNDBG_CONTROL               | 0x400000f1              |
| HV_X64_MSR_SYNDBG_STATUS                | 0x400000f2              |
| HV_X64_MSR_SYNDBG_SEND_BUFFER           | 0x400000f3              |
| HV_X64_MSR_SYNDBG_RECV_BUFFER           | 0x400000f4              |
| HV_X64_MSR_SYNDBG_PENDING_BUFFER        | 0x400000f5              |
| HV_X64_MSR_SYNDBG_OPTIONS               | 0x400000ff              |
| HV_X64_MSR_TSC_INVARIANT_CONTROL        | 0x40000118              |

### ARM registers excluded from guest CPU configuration dump

| Register name         | ID                 |
| --------------------- | ------------------ |
| Program Counter       | 0x6030000000100040 |
| KVM_REG_ARM_TIMER_CNT | 0x603000000013df1a |
