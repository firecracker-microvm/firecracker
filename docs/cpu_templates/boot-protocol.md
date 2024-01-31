# Boot protocol register settings

Firecracker makes certain modifications to the guest's registers regardless of
whether a CPU template is used to comply with the boot protocol. If a CPU
template is used the boot protocol settings are performed _after_ the CPU
template is applied. That means that if the CPU template configures CPUID bits
used in the boot protocol settings, they will be overwritten.

See also: [CPUID normalization](cpuid-normalization.md)

## Boot protocol MSRs (x86_64 only)

On x86_64, the following MSRs are set to `0`:

- MSR_IA32_SYSENTER_CS
- MSR_IA32_SYSENTER_ESP
- MSR_IA32_SYSENTER_EIP
- MSR_STAR
- MSR_CSTAR
- MSR_KERNEL_GS_BASE
- MSR_SYSCALL_MASK
- MSR_LSTAR
- MSR_IA32_TSC

and MSR_IA32_MISC_ENABLE is set to `1`.

## Boot protocol ARM registers (aarch64 only)

On aarch64, the following registers are set:

- PSTATE to PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT
- PC to kernel load address (vCPU0 only)
- X0 to DTB/FDT address (vCPU0 only)
