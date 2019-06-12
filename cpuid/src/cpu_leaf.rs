// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Basic CPUID Information
pub mod leaf_0x1 {
    pub const LEAF_NUM: u32 = 0x1;

    pub mod eax {

        pub const EXTENDED_FAMILY_ID_SHIFT: u32 = 20;
        pub const EXTENDED_PROCESSOR_MODEL_SHIFT: u32 = 16;
        pub const PROCESSOR_TYPE_SHIFT: u32 = 12;
        pub const PROCESSOR_FAMILY_SHIFT: u32 = 8;
        pub const PROCESSOR_MODEL_SHIFT: u32 = 4;
    }

    pub mod ebx {
        use bit_helper::BitRange;

        // The bit-range containing the (fixed) default APIC ID.
        pub const APICID_BITRANGE: BitRange = bit_range!(31, 24);
        // The bit-range containing the logical processor count.
        pub const CPU_COUNT_BITRANGE: BitRange = bit_range!(23, 16);
        // The bit-range containing the number of bytes flushed when executing CLFLUSH.
        pub const CLFLUSH_SIZE_BITRANGE: BitRange = bit_range!(15, 8);
    }

    pub mod ecx {
        // DTES64 = 64-bit debug store
        pub const DTES64_SHIFT: u32 = 2;
        // MONITOR = Monitor/MWAIT
        pub const MONITOR_SHIFT: u32 = 3;
        // CPL Qualified Debug Store
        pub const DS_CPL_SHIFT: u32 = 4;
        // 5 = VMX (Virtual Machine Extensions)
        // 6 = SMX (Safer Mode Extensions)
        // 7 = EIST (Enhanced Intel SpeedStep® technology)
        // TM2 = Thermal Monitor 2
        pub const TM2_SHIFT: u32 = 8;
        // CNXT_ID = L1 Context ID (L1 data cache can be set to adaptive/shared mode)
        pub const CNXT_ID: u32 = 10;
        // SDBG (cpu supports IA32_DEBUG_INTERFACE MSR for silicon debug)
        pub const SDBG_SHIFT: u32 = 11;
        pub const FMA_SHIFT: u32 = 12;
        // XTPR_UPDATE = xTPR Update Control
        pub const XTPR_UPDATE_SHIFT: u32 = 14;
        // PDCM = Perfmon and Debug Capability
        pub const PDCM_SHIFT: u32 = 15;
        // 18 = DCA Direct Cache Access (prefetch data from a memory mapped device)
        pub const MOVBE_SHIFT: u32 = 22;
        pub const TSC_DEADLINE_TIMER_BITINDEX: u32 = 24;
        pub const OSXSAVE_SHIFT: u32 = 27;
        // Cpu is running on a hypervisor.
        pub const HYPERVISOR_BITINDEX: u32 = 31;
    }

    pub mod edx {
        pub const PSN_SHIFT: u32 = 18; // Processor Serial Number
        pub const DS_SHIFT: u32 = 21; // Debug Store.
        pub const ACPI_SHIFT: u32 = 22; // Thermal Monitor and Software Controlled Clock Facilities.
        pub const SS_SHIFT: u32 = 27; // Self Snoop
        pub const HTT: u32 = 28; // Max APIC IDs reserved field is valid
        pub const TM_SHIFT: u32 = 29; // Thermal Monitor.
        pub const PBE_SHIFT: u32 = 31; // Pending Break Enable.
    }
}

pub mod leaf_cache_parameters {
    pub mod eax {
        use bit_helper::BitRange;

        pub const CACHE_LEVEL_BITRANGE: BitRange = bit_range!(7, 5);
        pub const MAX_CPUS_PER_CORE_BITRANGE: BitRange = bit_range!(25, 14);
    }
}

// Deterministic Cache Parameters Leaf
pub mod leaf_0x4 {
    pub const LEAF_NUM: u32 = 0x4;

    pub mod eax {
        use bit_helper::BitRange;

        // inherit eax from leaf_cache_parameters
        pub use cpu_leaf::leaf_cache_parameters::eax::*;

        pub const MAX_CORES_PER_PACKAGE_BITRANGE: BitRange = bit_range!(31, 26);
    }
}

// Thermal and Power Management Leaf
pub mod leaf_0x6 {
    pub const LEAF_NUM: u32 = 0x6;

    pub mod eax {
        pub const TURBO_BOOST_BITINDEX: u32 = 1;
    }

    pub mod ecx {
        // "Energy Performance Bias" bit.
        pub const EPB_BITINDEX: u32 = 3;
    }
}

// Structured Extended Feature Flags Enumeration Leaf
pub mod leaf_0x7 {
    pub const LEAF_NUM: u32 = 0x7;

    pub mod index0 {
        pub mod ebx {
            // 1 = TSC_ADJUST
            pub const SGX_SHIFT: u32 = 2;
            pub const BMI1_SHIFT: u32 = 3;
            pub const HLE_SHIFT: u32 = 4;
            pub const AVX2_SHIFT: u32 = 5;
            // FPU Data Pointer updated only on x87 exceptions if 1.
            pub const FPDP_SHIFT: u32 = 6;
            // 7 = SMEP (Supervisor-Mode Execution Prevention if 1)
            pub const BMI2_SHIFT: u32 = 8;
            // 9 = Enhanced REP MOVSB/STOSB if 1
            // 10 = INVPCID
            pub const INVPCID_SHIFT: u32 = 10;
            pub const RTM_SHIFT: u32 = 11;
            // Intel® Resource Director Technology (Intel® RDT) Monitoring
            pub const RDT_M_SHIFT: u32 = 12;
            // 13 = Deprecates FPU CS and FPU DS values if 1
            // 14 = MPX (Intel® Memory Protection Extensions)
            // RDT = Intel® Resource Director Technology
            pub const RDT_A_SHIFT: u32 = 15;
            // AVX-512 Foundation instructions
            pub const AVX512F_SHIFT: u32 = 16;
            // AVX-512 Doubleword and Quadword Instructions
            pub const AVX512DQ_SHIFT: u32 = 17;
            pub const RDSEED_SHIFT: u32 = 18;
            pub const ADX_SHIFT: u32 = 19;
            // 20 = SMAP (Supervisor-Mode Access Prevention)
            // AVX512IFMA = AVX-512 Integer Fused Multiply-Add Instructions
            pub const AVX512IFMA_SHIFT: u32 = 21;
            // 21 = PCOMMIT intruction
            // 23 = CLFLUSH_OPT (flushing multiple cache lines in parallel within a single logical processor)
            // 24 = CLWB (Cache Line Write Back)
            // PT = Intel Processor Trace
            pub const PT_SHIFT: u32 = 25;
            // AVX512PF = AVX512 Prefetch Instructions
            pub const AVX512PF_SHIFT: u32 = 26;
            // AVX512ER = AVX-512 Exponential and Reciprocal Instructions
            pub const AVX512ER_SHIFT: u32 = 27;
            // AVX512CD = AVX-512 Conflict Detection Instructions
            pub const AVX512CD_SHIFT: u32 = 28;
            // Intel Secure Hash Algorithm Extensions
            pub const SHA_SHIFT: u32 = 29;
            // AVX-512 Byte and Word Instructions
            pub const AVX512BW_SHIFT: u32 = 30;
            // AVX-512 Vector Length Extensions
            pub const AVX512VL_SHIFT: u32 = 31;
        }

        pub mod ecx {
            // 0 = PREFETCHWT1 (move data closer to the processor in anticipation of future use)
            // AVX512_VBMI = AVX-512 Vector Byte Manipulation Instructions
            pub const AVX512_VBMI_SHIFT: u32 = 1;
            // 2 = UMIP (User Mode Instruction Prevention)
            // 3 = PKU (Protection Keys for user-mode pages)
            // 4 = OSPKE (If 1, OS has set CR4.PKE to enable protection keys)
            // 5 = WAITPKG
            // 7-6 reserved
            // 8 = GFNI
            // 13-09 reserved
            // AVX512_VPOPCNTDQ = Vector population count instruction (Intel® Xeon Phi™ only.)
            pub const AVX512_VPOPCNTDQ_SHIFT: u32 = 14;
            // 21 - 17 = The value of MAWAU used by the BNDLDX and BNDSTX instructions in 64-bit mode.
            // Read Processor ID
            pub const RDPID_SHIFT: u32 = 22;
            // 23 - 29 reserved
            // SGX_LC = SGX Launch Configuration
            pub const SGX_LC_SHIFT: u32 = 30;
            // 31 reserved
        }

        pub mod edx {
            // AVX-512 4-register Neural Network Instructions
            pub const AVX512_4VNNIW_SHIFT: u32 = 2;
            // AVX-512 4-register Multiply Accumulation Single precision
            pub const AVX512_4FMAPS_SHIFT: u32 = 3;
            pub const ARCH_CAPABILITIES_BITINDEX: u32 = 29;
        }
    }
}

pub mod leaf_0xa {
    pub const LEAF_NUM: u32 = 0xa;
}

// Extended Topology Leaf
pub mod leaf_0xb {
    pub const LEAF_NUM: u32 = 0xb;

    pub const LEVEL_TYPE_INVALID: u32 = 0;
    pub const LEVEL_TYPE_THREAD: u32 = 1;
    pub const LEVEL_TYPE_CORE: u32 = 2;

    pub mod eax {
        use bit_helper::BitRange;

        // The bit-range containing the number of bits to shift right the APIC ID in order to get
        // the next level APIC ID
        pub const APICID_BITRANGE: BitRange = bit_range!(4, 0);
    }

    pub mod ebx {
        use bit_helper::BitRange;

        // The bit-range containing the number of factory-configured logical processors
        // at the current cache level
        pub const NUM_LOGICAL_PROCESSORS_BITRANGE: BitRange = bit_range!(15, 0);
    }

    pub mod ecx {
        use bit_helper::BitRange;

        pub const LEVEL_TYPE_BITRANGE: BitRange = bit_range!(15, 8);
        pub const LEVEL_NUMBER_BITRANGE: BitRange = bit_range!(7, 0);
    }
}

// Processor Extended State Enumeration Sub-leaves
pub mod leaf_0xd {
    pub const LEAF_NUM: u32 = 0xd;

    pub mod eax {
        use bit_helper::BitRange;

        pub const AVX512_STATE_BITRANGE: BitRange = bit_range!(7, 5);
    }
}

pub mod leaf_0x80000000 {
    pub const LEAF_NUM: u32 = 0x8000_0000;

    pub mod eax {
        use bit_helper::BitRange;

        pub const LARGEST_EXTENDED_FN_BITRANGE: BitRange = bit_range!(31, 0);
    }
}

pub mod leaf_0x80000001 {
    pub const LEAF_NUM: u32 = 0x8000_0001;

    pub mod ecx {
        pub const LZCNT_SHIFT: u32 = 5; // advanced bit manipulation
        pub const PREFETCH_SHIFT: u32 = 8; // 3DNow! PREFETCH/PREFETCHW instructions
        pub const TOPOEXT_INDEX: u32 = 22;
    }

    pub mod edx {
        pub const PDPE1GB_SHIFT: u32 = 26; // 1-GByte pages are available if 1.
    }
}

pub mod leaf_0x80000008 {
    pub const LEAF_NUM: u32 = 0x8000_0008;

    pub mod ecx {
        use bit_helper::BitRange;

        // The number of bits in the initial ApicId value that indicate thread ID within a package
        // Possible values:
        // 0-3 -> Reserved
        // 4 -> 1 Die, up to 16 threads
        // 5 -> 2 Die, up to 32 threads
        // 6 -> 3,4 Die, up to 64 threads
        pub const THREAD_ID_SIZE_BITRANGE: BitRange = bit_range!(15, 12);
        // The number of threads in the package - 1
        pub const NUM_THREADS_BITRANGE: BitRange = bit_range!(7, 0);
    }
}

// Extended Cache Topology Leaf
pub mod leaf_0x8000001d {
    pub const LEAF_NUM: u32 = 0x8000_001d;

    // inherit eax from leaf_cache_parameters
    pub use cpu_leaf::leaf_cache_parameters::eax;
}

// Extended APIC ID Leaf
pub mod leaf_0x8000001e {
    pub const LEAF_NUM: u32 = 0x8000_001e;

    pub mod eax {
        use bit_helper::BitRange;

        pub const EXTENDED_APIC_ID_BITRANGE: BitRange = bit_range!(31, 0);
    }

    pub mod ebx {
        use bit_helper::BitRange;

        // The number of threads per core - 1
        pub const THREADS_PER_CORE_BITRANGE: BitRange = bit_range!(15, 8);
        pub const CORE_ID_BITRANGE: BitRange = bit_range!(7, 0);
    }

    pub mod ecx {
        use bit_helper::BitRange;

        // The number of nodes per processor. Possible values:
        // 0 -> 1 node per processor
        // 1 -> 2 nodes per processor
        // 2 -> Reserved
        // 3 -> 4 nodes per processor
        pub const NODES_PER_PROCESSOR_BITRANGE: BitRange = bit_range!(10, 8);
        pub const NODE_ID_BITRANGE: BitRange = bit_range!(7, 0);
    }
}
