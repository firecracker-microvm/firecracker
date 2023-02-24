// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::bitfield;

// -------------------------------------------------------------------------------------------------
// Leaf 1
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf1Eax, u32, {
    /// Stepping ID.
    stepping_id: 0..4,
    /// Model.
    model: 4..8,
    /// Family ID.
    family_id: 8..12,
    /// Processor Type.
    processor_type: 12..14,
    /// Extended Model ID.
    extended_model_id: 16..20,
    /// Extended Family ID.
    extended_family_id: 20..28,
});

bitfield!(Leaf1Ebx, u32, {
    /// Brand Index.
    brand_index: 0..8,
    /// CLFLUSH line size (Value ∗ 8 = cache line size in bytes; used also by CLFLUSHOPT).
    clflush: 8..16,
    /// Maximum number of addressable IDs for logical processors in this physical package.
    ///
    /// The nearest power-of-2 integer that is not smaller than EBX[23:16] is the number of unique
    /// initial APIC IDs reserved for addressing different logical processors in a physical package.
    /// This field is only valid if CPUID.1.EDX.HTT[bit 28]= 1.
    max_addressable_logical_processor_ids: 16..24,
    /// Initial APIC ID.
    ///
    /// The 8-bit initial APIC ID in EBX[31:24] is replaced by the 32-bit x2APIC ID, available in
    /// Leaf 0BH and Leaf 1FH.
    initial_apic_id: 24..32,
});

bitfield!(Leaf1Ecx, u32, {
    /// Streaming SIMD Extensions 3 (SSE3). A value of 1 indicates the processor supports this
    /// technology.
    sse3: 0,
    /// PCLMULQDQ. A value of 1 indicates the processor supports the PCLMULQDQ instruction.
    pclmulqdq: 1,
    /// 64-bit DS Area. A value of 1 indicates the processor supports DS area using 64-bit layout.
    dtes64: 2,
    /// MONITOR/MWAIT. A value of 1 indicates the processor supports this feature.
    monitor: 3,
    /// CPL Qualified Debug Store. A value of 1 indicates the processor supports the extensions to
    /// the Debug Store feature to allow for branch message storage qualified by CPL.
    ds_cpl: 4,
    /// Virtual Machine Extensions. A value of 1 indicates that the processor supports this
    /// technology.
    vmx: 5,
    /// Safer Mode Extensions. A value of 1 indicates that the processor supports this technology.
    /// See Chapter 6, “Safer Mode Extensions Reference”.
    smx: 6,
    /// Enhanced Intel SpeedStep® technology. A value of 1 indicates that the processor supports
    /// this technology.
    eist: 7,
    /// Thermal Monitor 2. A value of 1 indicates whether the processor supports this technology.
    tm2: 8,
    /// A value of 1 indicates the presence of the Supplemental Streaming SIMD Extensions 3 (SSSE3).
    /// A value of 0 indicates the instruction extensions are not present in the processor.
    ssse3: 9,
    /// L1 Context ID. A value of 1 indicates the L1 data cache mode can be set to either adaptive
    /// mode or shared mode. A value of 0 indicates this feature is not supported. See definition of
    /// the IA32_MISC_ENABLE MSR Bit 24 (L1 Data Cache Context Mode) for details.
    cnxt_id: 10,
    /// A value of 1 indicates the processor supports IA32_DEBUG_INTERFACE MSR for silicon debug.
    sdbg: 11,
    /// A value of 1 indicates the processor supports FMA extensions using YMM state.
    fma: 12,
    /// CMPXCHG16B Available. A value of 1 indicates that the feature is available. See the
    /// “CMPXCHG8B/CMPXCHG16B—Compare and Exchange Bytes” section in this chapter for a description.
    cmpxchg16b: 13,
    /// xTPR Update Control. A value of 1 indicates that the processor supports changing
    /// IA32_MISC_ENABLE[bit 23].
    xtpr_update_control: 14,
    /// Perfmon and Debug Capability: A value of 1 indicates the processor supports the performance
    /// and debug feature indication MSR IA32_PERF_CAPABILITIES.
    pdcm: 15,
    // Reserved
    /// Process-context identifiers. A value of 1 indicates that the processor supports PCIDs and
    /// that software may set CR4.PCIDE to 1.
    pcid: 17,
    /// A value of 1 indicates the processor supports the ability to prefetch data from a memory
    /// mapped device.
    dca: 18,
    /// A value of 1 indicates that the processor supports SSE4.1.
    sse4_1: 19,
    /// A value of 1 indicates that the processor supports SSE4.2.
    sse4_2: 20,
    /// A value of 1 indicates that the processor supports x2APIC feature.
    x2apic: 21,
    /// A value of 1 indicates that the processor supports MOVBE instruction.
    movbe: 22,
    /// A value of 1 indicates that the processor supports the POPCNT instruction.
    popcnt: 23,
    /// A value of 1 indicates that the processor’s local APIC timer supports one-shot operation
    /// using a TSC deadline value.
    tsc_deadline: 24,
    /// A value of 1 indicates that the processor supports the AESNI instruction extensions.
    aesni: 25,
    /// A value of 1 indicates that the processor supports the XSAVE/XRSTOR processor extended
    /// states feature, the XSETBV/XGETBV instructions, and XCR0.
    xsave: 26,
    /// A value of 1 indicates that the OS has set CR4.OSXSAVE[bit 18] to enable XSETBV/XGETBV
    /// instructions to access XCR0 and to support processor extended state management using
    /// XSAVE/XRSTOR.
    osxsave: 27,
    /// A value of 1 indicates the processor supports the AVX instruction extensions.
    avx: 28,
    /// A value of 1 indicates that processor supports 16-bit floating-point conversion instructions.
    f16c: 29,
    /// A value of 1 indicates that processor supports RDRAND instruction.
    rdrand: 30,
    // Not used
});

bitfield!(Leaf1Edx, u32, {
    /// Floating Point Unit On-Chip. The processor contains an x87 FPU.
    fpu: 0,
    /// Virtual 8086 Mode Enhancements. Virtual 8086 mode enhancements, including CR4.VME for
    /// controlling the feature, CR4.PVI for protected mode virtual interrupts, software interrupt
    /// indirection, expansion of the TSS with the software indirection bitmap, and EFLAGS.VIF and
    /// EFLAGS.VIP flags.
    vme: 1,
    /// Debugging Extensions. Support for I/O breakpoints, including CR4.DE for controlling the
    /// feature, and optional trapping of accesses to DR4 and DR5.
    de: 2,
    /// Page Size Extension. Large pages of size 4 MByte are supported, including CR4.PSE for
    /// controlling the feature, the defined dirty bit in PDE (Page Directory Entries), optional
    /// reserved bit trapping in CR3, PDEs, and PTEs.
    pse: 3,
    /// Time Stamp Counter. The RDTSC instruction is supported, including CR4.TSD for controlling
    /// privilege.
    tsc: 4,
    /// Model Specific Registers RDMSR and WRMSR Instructions. The RDMSR and WRMSR instructions are
    /// supported. Some of the MSRs are implementation dependent.
    msr: 5,
    /// Physical Address Extension. Physical addresses greater than 32 bits are supported: extended
    /// page table entry formats, an extra level in the page translation tables is defined, 2-MByte
    /// pages are supported instead of 4 Mbyte pages if PAE bit is 1.
    pae: 6,
    /// Machine Check Exception. Exception 18 is defined for Machine Checks, including CR4.MCE for
    /// controlling the feature. This feature does not define the model-specific implementations of
    /// machine-check error logging, reporting, and processor shutdowns. Machine Check exception
    /// handlers may have to depend on processor version to do model specific processing of the
    /// exception, or test for the presence of the Machine Check feature.
    mce: 7,
    /// CMPXCHG8B Instruction. The compare-and-exchange 8 bytes (64 bits) instruction is supported
    /// (implicitly locked and atomic).
    cx8: 8,
    /// APIC On-Chip. The processor contains an Advanced Programmable Interrupt Controller (APIC),
    /// responding to memory mapped commands in the physical address range FFFE0000H to FFFE0FFFH
    /// (by default - some processors permit the APIC to be relocated).
    apic: 9,
    // Reserved
    /// SYSENTER and SYSEXIT Instructions. The SYSENTER and SYSEXIT and associated MSRs are
    /// supported.
    sep: 11,
    /// Memory Type Range Registers. MTRRs are supported. The MTRRcap MSR contains feature bits that
    /// describe what memory types are supported, how many variable MTRRs are supported, and whether
    /// fixed MTRRs are supported.
    mtrr: 12,
    /// Page Global Bit. The global bit is supported in paging-structure entries that map a page,
    /// indicating TLB entries that are common to different processes and need not be flushed. The
    /// CR4.PGE bit controls this feature.
    pge: 13,
    /// Machine Check Architecture. A value of 1 indicates the Machine Check Architecture of
    /// reporting machine errors is supported. The MCG_CAP MSR contains feature bits describing how
    /// many banks of error reporting MSRs are supported.
    mca: 14,
    /// Conditional Move Instructions. The conditional move instruction CMOV is supported. In
    /// addition, if x87 FPU is present as indicated by the CPUID.FPU feature bit, then the FCOMI
    /// and FCMOV instructions are supported
    cmov: 15,
    /// Page Attribute Table. Page Attribute Table is supported. This feature augments the Memory
    /// Type Range Registers (MTRRs), allowing an operating system to specify attributes of memory
    /// accessed through a linear address on a 4KB granularity.
    pat: 16,
    /// 36-Bit Page Size Extension. 4-MByte pages addressing physical memory beyond 4 GBytes are
    /// supported with 32-bit paging. This feature indicates that upper bits of the physical address
    /// of a 4-MByte page are encoded in bits 20:13 of the page-directory entry. Such physical
    /// addresses are limited by MAXPHYADDR and may be up to 40 bits in size.
    pse3_36: 17,
    /// Processor Serial Number. The processor supports the 96-bit processor identification number
    /// feature and the feature is enabled.
    psn: 18,
    /// CLFLUSH Instruction. CLFLUSH Instruction is supported.
    clfsh: 19,
    // Reserved
    /// Debug Store. The processor supports the ability to write debug information into a memory
    /// resident buffer. This feature is used by the branch trace store (BTS) and processor
    /// event-based sampling (PEBS) facilities (see Chapter 23, “Introduction to Virtual-Machine
    /// Extensions,” in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume
    /// 3C).
    ds: 21,
    /// Thermal Monitor and Software Controlled Clock Facilities. The processor implements internal
    /// MSRs that allow processor temperature to be monitored and processor performance to be
    /// modulated in predefined duty cycles under software control.
    acpi: 22,
    /// Intel MMX Technology. The processor supports the Intel MMX technology.
    mmx: 23,
    /// FXSAVE and FXRSTOR Instructions. The FXSAVE and FXRSTOR instructions are supported for fast
    /// save and restore of the floating point context. Presence of this bit also indicates that
    /// CR4.OSFXSR is available for an operating system to indicate that it supports the FXSAVE and
    /// FXRSTOR instructions.
    fxsr: 24,
    /// SSE. The processor supports the SSE extensions.
    sse: 25,
    /// SSE2. The processor supports the SSE2 extensions.
    sse2: 26,
    /// Self Snoop. The processor supports the management of conflicting memory types by performing
    /// a snoop of its own cache structure for transactions issued to the bus.
    ss: 27,
    /// Max APIC IDs reserved field is Valid. A value of 0 for HTT indicates there is only a single
    /// logical processor in the package and software should assume only a single APIC ID is
    /// reserved. A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16] (the Maximum number
    /// of addressable IDs for logical processors in this package) is valid for the package.
    htt: 28,
    /// Thermal Monitor. The processor implements the thermal monitor automatic thermal control circuitry (TCC).
    tm: 29,
    // Reserved
    /// Pending Break Enable. The processor supports the use of the FERR#/PBE# pin when the
    /// processor is in the stop-clock state (STPCLK# is asserted) to signal the processor that an
    /// interrupt is pending and that the processor should return to normal operation to handle the
    /// interrupt.
    pbe: 31,
});

// -------------------------------------------------------------------------------------------------
// Leaf 80000002
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf80000002Eax, u32, {
    /// Processor Brand String.
    processor_brand_string: 0..32,
});

bitfield!(Leaf80000002Ebx, u32, {
    /// Processor Brand String Continued.
    processor_brand_string: 0..32,
});

bitfield!(Leaf80000002Ecx, u32, {
    /// Processor Brand String Continued.
    processor_brand_string: 0..32,
});

bitfield!(Leaf80000002Edx, u32, {
    /// Processor Brand String Continued.
    processor_brand_string: 0..32,
});
