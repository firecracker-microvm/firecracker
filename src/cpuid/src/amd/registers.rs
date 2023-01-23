// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::bitfield;

// -------------------------------------------------------------------------------------------------
// Leaf 7
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf7Eax, u32, {
    /// Returns the number of subfunctions supported.
    max_sub_fn: 0..32,
});

bitfield!(Leaf7Ebx, u32, {
    /// FS and GS base read/write instruction support.
    fsgsbase: 0,
    // Reserved
    /// Bit manipulation group 1 instruction support.
    bmi1: 3,
    // Reserved
    /// A value of 1 indicates that the processor supports SSE4.1.
    avx2: 5,
    // Reserved
    /// Supervisor mode execution prevention.
    smep: 7,
    /// Bit manipulation group 2 instruction support.
    bmi2: 8,
    // Reserved
    /// INVPCID instruction support.
    invpcid: 10,
    // Reserved
    /// RDSEED instruction support.
    rdseed: 18,
    /// ADCX, ADOX instruction support.
    adx: 19,
    /// Supervisor mode access prevention.
    smap: 20,
    // Reserved
    /// RDPID instruction and TSC_AUX MSR support.
    rdpid: 22,
    /// CLFLUSHOPT instruction support.
    clflushopt: 23,
    /// CLWB instruction support.
    clwb: 24,
    // Reserved
    /// Secure Hash Algorithm instruction extension.
    sha: 29,
    // Reserved
});

bitfield!(Leaf7Ecx, u32, {
    // Reserved
    /// User mode instruction prevention support.
    umip: 0,
    /// Memory Protection Keys supported.
    pku: 3,
    /// OS has enabled Memory Protection Keys and use of the RDPKRU/WRPKRU
    /// instructions by setting CR4.PKE=1.
    ospke: 4,
    // Reserved
    /// Shadow Stacks supported.
    cet_ss: 7,
    // Reserved
    /// Support for VAES 256-bit instructions.
    vaes: 9,
    /// Support for VPCLMULQDQ 256-bit instruction.
    vpcmulqdq: 10,
    // Reserved
});

bitfield!(Leaf7Edx, u32, {
    // Reserved
});

// -------------------------------------------------------------------------------------------------
// Leaf 80000000
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf80000000Eax, u32, {
    /// Largest extended function. The largest CPUID extended function input value supported by the processor implementation.
    l_func_ext: 0..32,
});

bitfield!(Leaf80000000Ebx, u32, {
    /// Four characters of the 12-byte character string (encoded in ASCII) “AuthenticAMD”.
    vendor: 0..32,
});

bitfield!(Leaf80000000Ecx, u32, {
    /// Four characters of the 12-byte character string (encoded in ASCII) “AuthenticAMD”.
    vendor: 0..32,
});

bitfield!(Leaf80000000Edx, u32, {
    /// Four characters of the 12-byte character string (encoded in ASCII) “AuthenticAMD”.
    vendor: 0..32,
});
// -------------------------------------------------------------------------------------------------
// Leaf 80000001
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf80000001Eax, u32, {
    family_model_stepping: 0..32,
});

bitfield!(Leaf80000001Ebx, u32, {
    /// Brand ID. This field, in conjunction with CPUID Fn0000_0001_EBX[8BitBrandId], is used by system firmware to generate the processor name string. See your processor revision guide for how to program the processor name string.
    brand_id: 0..16,
    // Reserved.
    /// Package type. If (Family[7:0] >= 10h), this field is valid. If (Family[7:0]<10h), this field is reserved.
    pkg_type: 28..32,
});

bitfield!(Leaf80000001Ecx, u32, {
    /// LAHF and SAHF instruction support in 64-bit mode. See “LAHF” and “SAHF” in APM3.
    lahf_sahf: 0,
    /// Core multi-processing legacy mode. See “Legacy Method” on page 633.
    cmp_legacy: 1,
    /// Secure virtual machine. See “Secure Virtual Machine” in APM2.
    svm: 2,
    /// Extended APIC space. This bit indicates the presence of extended APIC register space starting at offset 400h from the “APIC Base Address Register,” as specified in the BKDG.
    ext_apic_space: 3,
    /// LOCK MOV CR0 means MOV CR8. See “MOV(CRn)” in APM3.
    alt_mov_cr_8: 4,
    /// Advanced bit manipulation. LZCNT instruction support. See “LZCNT” in APM3.
    abm: 5,
    /// EXTRQ, INSERTQ, MOVNTSS, and MOVNTSD instruction support. See “EXTRQ”, “INSERTQ”, “MOVNTSS”, and “MOVNTSD” in APM4.
    sse4a: 6,
    /// Misaligned SSE mode. See “Misaligned Access Support Added for SSE Instructions” in APM1.
    mis_align_sse: 7,
    /// PREFETCH and PREFETCHW instruction support. See “PREFETCH” and “PREFETCHW” in APM3.
    d3_now_prefetch: 8,
    /// OS visible workaround. Indicates OS-visible workaround support. See “OS Visible Work-around (OSVW) Information” in APM2.
    osvw: 9,
    /// Instruction based sampling. See “Instruction Based Sampling” in APM2.
    ibs: 10,
    /// Extended operation support.
    xop: 11,
    /// SKINIT and STGI are supported. Indicates support for SKINIT and STGI, independent of the value of MSRC000_0080[SVME]. See APM2 and APM3.
    skinit: 12,
    /// Watchdog timer support. See APM2 and APM3. Indicates support for MSRC001_0074.
    wdt: 13,
    // Reserved.
    /// Lightweight profiling support. See “Lightweight Profiling” in APM2 and reference pages for individual LWP instructions in APM3.
    lwp: 15,
    /// Four-operand FMA instruction support.
    fma4: 16,
    /// Translation Cache Extension support.
    tce: 17,
    // Reserved.
    /// Trailing bit manipulation instruction support.
    tbm: 21,
    /// Topology extensions support. Indicates support for CPUID Fn8000_001D_EAX_x[N:0]-CPUID Fn8000_001E_EDX.
    topology_extensions: 22,
    /// Processor performance counter extensions support. Indicates support for MSRC001_020[A,8,6,4,2,0] and MSRC001_020[B,9,7,5,3,1].
    perf_ctr_ext_core: 23,
    /// NB performance counter extensions support. Indicates support for MSRC001_024[6,4,2,0] and MSRC001_024[7,5,3,1].
    perf_ctr_ext_nb: 24,
    // Reserved.
    /// Data access breakpoint extension. Indicates support for MSRC001_1027 and MSRC001_101[B:9].
    data_bkpt_ext: 26,
    /// Performance time-stamp counter. Indicates support for MSRC001_0280 [Performance Time Stamp Counter].
    perf_tsc: 27,
    /// Support for L3 performance counter extension.
    perf_ctr_ext_llc: 28,
    /// Support for MWAITX and MONITORX instructions.
    monitor_x: 29,
    /// Breakpoint Addressing masking extended to bit 31.
    add_mask_ext: 30,
    // Reserved.
});

bitfield!(Leaf80000001Edx, u32, {
    /// x87 floating-point unit on-chip. Same as CPUID Fn0000_0001_EDX[FPU].
    fpu: 0,
    /// Virtual-mode enhancements. Same as CPUID Fn0000_0001_EDX[VME].
    vme: 1,
    /// Debugging extensions. Same as CPUID Fn0000_0001_EDX[DE].
    de: 2,
    /// Page-size extensions. Same as CPUID Fn0000_0001_EDX[PSE].
    pse: 3,
    /// Time stamp counter. Same as CPUID Fn0000_0001_EDX[TSC].
    tsc: 4,
    /// AMD model-specific registers. Same as CPUID Fn0000_0001_EDX[MSR].
    msr: 5,
    /// Physical-address extensions. Same as CPUID Fn0000_0001_EDX[PAE].
    pae: 6,
    /// Machine check exception. Same as CPUID Fn0000_0001_EDX[MCE].
    mce: 7,
    /// CMPXCHG8B instruction. Same as CPUID Fn0000_0001_EDX[CMPXCHG8B].
    cmpxchg8b: 8,
    /// Advanced programmable interrupt controller. Same as CPUID Fn0000_0001_EDX[APIC].
    apic: 9,
    // Reserved.
    /// SYSCALL and SYSRET instructions. See “SYSCALL” and “SYSRET” in APM3.
    sys_call_sys_ret: 11,
    /// Memory-type range registers. Same as CPUID Fn0000_0001_EDX[MTRR].
    mtrr: 12,
    /// Page global extension. Same as CPUID Fn0000_0001_EDX[PGE].
    pge: 13,
    /// Machine check architecture. Same as CPUID Fn0000_0001_EDX[MCA].
    mca: 14,
    /// Conditional move instructions. Same as CPUID Fn0000_0001_EDX[CMOV].
    cmov: 15,
    /// Page attribute table. Same as CPUID Fn0000_0001_EDX[PAT].
    pat: 16,
    /// Page-size extensions. Same as CPUID Fn0000_0001_EDX[PSE36].
    pse36: 17,
    // Reserved.
    /// No-execute page protection. See “Page Translation and Protection” in APM2.
    nx: 20,
    // Reserved.
    /// AMD extensions to MMX instructions. See Appendix D “Instruction Subsets and CPUID Feature Sets” in APM3 and “128-Bit Media and Scientific Programming” in APM1.
    mmx_ext: 22,
    /// MMX™ instructions. Same as CPUID Fn0000_0001_EDX[MMX].
    mmx: 23,
    /// FXSAVE and FXRSTOR instructions. Same as CPUID Fn0000_0001_EDX[FXSR].
    fxsr: 24,
    /// FXSAVE and FXRSTOR instruction optimizations. See “FXSAVE” and “FXRSTOR” in APM5.
    ffxsr: 25,
    /// 1-GB large page support. See “1-GB Paging Support” in APM2.
    page_1gb: 26,
    /// RDTSCP instruction. See “RDTSCP” in APM3.
    rdtscp: 27,
    // Reserved.
    /// Long mode. See “Processor Initialization and Long-Mode Activation” in APM2.
    lm: 29,
    /// AMD extensions to 3DNow! instructions. See Appendix D “Instruction Subsets and CPUID Feature Sets” in APM3.
    d3_now_ext: 30,
    /// 3DNow!™ instructions. See Appendix D “Instruction Subsets and CPUID Feature Sets” in APM3.
    d3_now: 31,
});
// -------------------------------------------------------------------------------------------------
// Leaf 80000008
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf80000008Eax, u32, {
    /// Maximum physical address size in bits. When GuestPhysAddrSize is zero, this field also indicates the maximum guest physical address size.
    phys_addr_size: 0..8,
    /// Maximum linear address size in bits.
    lin_addr_size: 8..16,
    /// Maximum guest physical address size in bits. This number applies only to guests using nested paging. When this field is zero, refer to the PhysAddrSize field for the maximum guest physical address size. See “Secure Virtual Machine” in APM2.
    guest_phys_addr_size: 16..24,
    // Reserved.
});

bitfield!(Leaf80000008Ebx, u32, {
    /// CLZERO instruction supported
    clzero: 0,
    /// Instruction Retired Counter MSR available
    inst_ret_cnt_msr: 1,
    /// FP Error Pointers Restored by XRSTOR
    rstr_fp_err_ptrs: 2,
    /// INVLPGB and TLBSYNC instruction supported
    invlpgb: 3,
    /// RDPRU instruction supported
    rdpru: 4,
    // Reserved.
    /// MCOMMIT instruction supported
    mcommit: 8,
    /// WBNOINVD instruction supported
    wbnoinvd: 9,
    // Reserved.
    /// Indirect Branch Prediction Barrier
    ibpd: 12,
    /// WBINVD/WBNOINVD are interruptible.
    int_wbinvd: 13,
    /// Indirect Branch Restricted Speculation
    ibrs: 14,
    /// Single Thread Indirect Branch Prediction mode
    stibp: 15,
    /// Processor prefers that IBRS be left on
    ibrs_always_on: 16,
    /// Processor prefers that STIBP be left on
    stibp_always_on: 17,
    /// IBRS is preferred over software solution
    ibrs_preferred: 18,
    /// IBRS provides same mode speculation limits
    ibrs_same_mode: 19,
    /// EFER.LMSLE is unsupported.
    efer_lmsle_unsupported: 20,
    /// INVLPGB support for invalidating guest nested translations
    invlpgb_nested_pages: 21,
    // Reserved.
    /// Speculative Store Bypass Disable
    ssbd: 24,
    /// Use VIRT_SPEC_CTL for SSBD
    ssbd_virt_spec_ctrl: 25,
    /// SSBD not needed on this processor
    ssbd_not_required: 26,
    // Reserved.
    /// Predictive Store Forward Disable
    psfd: 28,
    // Reserved.

});

bitfield!(Leaf80000008Ecx, u32, {
    /// Number of physical threads - 1. The number of threads in the processor is NT+1
    /// (e.g., if NT = 0, then there is one thread). See “Legacy Method” on page 633.
    nt: 0..8,
    // Reserved.
    /// APIC ID size. The number of bits in the initial APIC20[ApicId] value that indicate
    /// logical processor ID within a package. The size of this field determines the
    /// maximum number of logical processors (MNLP) that the package could
    /// theoretically support, and not the actual number of logical processors that are
    /// implemented or enabled in the package, as indicated by CPUID
    /// Fn8000_0008_ECX[NC]. A value of zero indicates that legacy methods must be
    /// used to determine the maximum number of logical processors, as indicated by
    /// CPUID Fn8000_0008_ECX[NC].
    apic_id_size: 12..16,
    /// Performance time-stamp counter size. Indicates the size of MSRC001_0280[PTSC].
    /// ```text
    /// Bits Description
    /// 00b 40 bits
    /// 01b 48 bits
    /// 10b 56 bits
    /// 11b 64 bits
    /// ```
    pref_tsc_size: 16..18,
    // Reserved.
});

bitfield!(Leaf80000008Edx, u32, {
    /// Maximum page count for INVLPGB instruction.
    invlpgb_count_max: 0..16,
    /// The maximum ECX value recognized by RDPRU.
    max_rdpru_id: 16..32,
});
// -------------------------------------------------------------------------------------------------
// Leaf 8000001D
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf8000001dEax, u32, {
    /// Cache type. Identifies the type of cache.
    /// ```text
    /// Bits Description
    /// 00h Null; no more caches.
    /// 01h Data cache
    /// 02h Instruction cache
    /// 03h Unified cache
    /// 1Fh-04h Reserved.
    /// ```
    cache_type: 0..4,
    /// Cache level. Identifies the level of this cache. Note that the enumeration value is
    /// not necessarily equal to the cache level.
    /// ```text
    /// Bits Description
    /// 000b Reserved.
    /// 001b Level 1
    /// 010b Level 2
    /// 011b Level 3
    /// 111b-100b Reserved.
    /// ```
    cache_level: 5..8,
    /// Self-initializing cache. When set, indicates that the cache is self initializing;
    /// software initialization not required. If 0 is returned in this field, hardware does not
    /// initialize this cache.
    self_initialization: 8,
    /// Fully associative cache. When set, indicates that the cache is fully associative. If
    /// 0 is returned in this field, the cache is set associative.
    fully_associative: 9,
    // Reserved.
    /// Specifies the number of logical processors sharing the cache enumerated by N,
    /// the value passed to the instruction in ECX. The number of logical processors
    /// sharing this cache is the value of this field incremented by 1. To determine which
    /// logical processors are sharing a cache, determine a Share Id for each processor
    /// as follows:
    ///
    /// ShareId = LocalApicId >> log2(NumSharingCache+1)
    ///
    /// Logical processors with the same ShareId then share a cache. If
    /// NumSharingCache+1 is not a power of two, round it up to the next power of two.
    num_sharing_cache: 14..26,
    // Reserved.
});

bitfield!(Leaf8000001dEbx, u32, {
    /// Cache line size. The cache line size in bytes is the value returned in this field
    /// incremented by 1.
    cache_line_size: 0..12,
    /// Number of physical line partitions. The number of physical line partitions is the
    /// value returned in this field incremented by 1.
    cache_phys_partitions: 12..22,
    /// Number of ways for this cache. The number of ways is the value returned in this
    /// field incremented by 1.
    cache_num_ways: 22..32,

});

bitfield!(Leaf8000001dEcx, u32, {
    /// Number of ways for set associative cache. Number of ways is the value returned in
    /// this field incremented by 1. Only valid for caches that are not fully associative
    /// (Fn8000_001D_EAX_xn[FullyAssociative] = 0).
    cache_num_sets: 0..32,
});

bitfield!(Leaf8000001dEdx, u32, {
    /// Write-Back Invalidate/Invalidate execution scope. A value of 0 returned in this field
    /// indicates that the WBINVD/INVD instruction invalidates all lower level caches of
    /// non-originating logical processors sharing this cache. When set, this field indicates
    /// that the WBINVD/INVD instruction is not guaranteed to invalidate all lower level
    /// caches of non-originating logical processors sharing this cache.
    wbinvd: 0,
    /// Cache inclusivity. A value of 0 indicates that this cache is not inclusive of lower
    /// cache levels. A value of 1 indicates that the cache is inclusive of lower cache
    /// levels.
    cache_inclusive: 1,
    // Reserved.
});
// -------------------------------------------------------------------------------------------------
// Leaf 8000001E
// -------------------------------------------------------------------------------------------------

bitfield!(Leaf8000001eEax, u32, {
    /// Extended APIC ID. If MSR0000_001B[ApicEn] = 0, this field is reserved..
    extended_apic_id: 0..32,
});

bitfield!(Leaf8000001eEbx, u32, {
    compute_unit_id: 0..8,
    /// Threads per compute unit (zero-based count). The actual number of threads
    /// per compute unit is the value of this field + 1. To determine which logical
    /// processors (threads) belong to a given Compute Unit, determine a ShareId
    /// for each processor as follows:
    ///
    /// ShareId = LocalApicId >> log2(ThreadsPerComputeUnit+1)
    ///
    /// Logical processors with the same ShareId then belong to the same Compute
    /// Unit. (If ThreadsPerComputeUnit+1 is not a power of two, round it up to the
    /// next power of two).
    threads_per_compute_unit: 8..16,
    // Reserved.

});

bitfield!(Leaf8000001eEcx, u32, {
    /// Specifies the ID of the node containing the current logical processor. NodeId
    /// values are unique across the system..
    node_id: 0..8,
    /// Specifies the number of nodes in the package/socket in which this logical
    /// processor resides. Node in this context corresponds to a processor die.
    /// Encoding is N-1, where N is the number of nodes present in the socket.
    nodes_per_processor: 8..10,
});

bitfield!(Leaf8000001eEdx, u32, {
    // Reserved.
});
