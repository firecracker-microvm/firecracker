// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Basic CPUID Information
pub mod leaf_0x1 {
    pub mod eax {
        pub const EXTENDED_FAMILY_ID_SHIFT: u32 = 20;
        pub const EXTENDED_PROCESSOR_MODEL_SHIFT: u32 = 16;
        pub const PROCESSOR_TYPE_SHIFT: u32 = 12;
        pub const PROCESSOR_FAMILY_SHIFT: u32 = 8;
        pub const PROCESSOR_MODEL_SHIFT: u32 = 4;
    }

    pub mod ebx {
        // The (fixed) default APIC ID.
        pub const APICID_SHIFT: u32 = 24;
        // Bytes flushed when executing CLFLUSH.
        pub const CLFLUSH_SIZE_SHIFT: u32 = 8;
        // The logical processor count.
        pub const CPU_COUNT_SHIFT: u32 = 16;
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
        pub const TSC_DEADLINE_TIMER_SHIFT: u32 = 24;
        pub const OSXSAVE_SHIFT: u32 = 27;
        // Cpu is running on a hypervisor.
        pub const HYPERVISOR_SHIFT: u32 = 31;
    }

    pub mod edx {
        pub const PSN_SHIFT: u32 = 18; // Processor Serial Number
        pub const DS_SHIFT: u32 = 21; // Debug Store.
        pub const ACPI_SHIFT: u32 = 22; // Thermal Monitor and Software Controlled Clock Facilities.
        pub const SS_SHIFT: u32 = 27; // Self Snoop
        pub const HTT_SHIFT: u32 = 28; // Max APIC IDs reserved field is valid
        pub const TM_SHIFT: u32 = 29; // Thermal Monitor.
        pub const PBE_SHIFT: u32 = 31; // Pending Break Enable.
    }
}

// Deterministic Cache Parameters Leaf
pub mod leaf_0x4 {
    pub mod eax {
        pub const CACHE_LEVEL: u32 = 5;
        pub const MAX_ADDR_IDS_SHARING_CACHE: u32 = 14;
        pub const MAX_ADDR_IDS_IN_PACKAGE: u32 = 26;
    }
}

// Thermal and Power Management Leaf
pub mod leaf_0x6 {
    pub mod eax {
        pub const TURBO_BOOST_SHIFT: u32 = 1;
    }

    pub mod ecx {
        // "Energy Performance Bias" bit.
        pub const EPB_SHIFT: u32 = 3;
    }
}

// Structured Extended Feature Flags Enumeration Leaf
pub mod leaf_0x7 {
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
            pub const RDSEED_SHIFT: u32 = 18;
            pub const ADX_SHIFT: u32 = 19;
            // 20 = SMAP (Supervisor-Mode Access Prevention)
            // 21 & 22 reserved
            // 23 = CLFLUSH_OPT (flushing multiple cache lines in parallel within a single logical processor)
            // 24 = CLWB (Cache Line Write Back)
            // PT = Intel Processor Trace
            pub const PT_SHIFT: u32 = 25;
            // AVX512CD = AVX512 Conflict Detection
            pub const AVX512CD_SHIFT: u32 = 28;
            // Intel Secure Hash Algorithm Extensions
            pub const SHA_SHIFT: u32 = 29;
            // 30 - 32 reserved
        }

        pub mod ecx {
            // 0 = PREFETCHWT1 (move data closer to the processor in anticipation of future use)
            // 1 = reserved
            // 2 = UMIP (User Mode Instruction Prevention)
            // 3 = PKU (Protection Keys for user-mode pages)
            // 4 = OSPKE (If 1, OS has set CR4.PKE to enable protection keys)
            // 5- 16 reserved
            // 21 - 17 = The value of MAWAU used by the BNDLDX and BNDSTX instructions in 64-bit mode.
            pub const RDPID_SHIFT: u32 = 22; // Read Processor ID
                                             // 23 - 29 reserved
                                             // SGX_LC = SGX Launch Configuration
            pub const SGX_LC_SHIFT: u32 = 30;
            // 31 reserved
        }
    }
}

pub mod leaf_0x80000001 {
    pub mod ecx {
        pub const PREFETCH_SHIFT: u32 = 8; // 3DNow! PREFETCH/PREFETCHW instructions
        pub const LZCNT_SHIFT: u32 = 5; // advanced bit manipulation
    }

    pub mod edx {
        pub const PDPE1GB_SHIFT: u32 = 26; // 1-GByte pages are available if 1.
    }
}

// Extended Topology Leaf
pub mod leaf_0xb {
    pub const LEVEL_TYPE_INVALID: u32 = 0;
    pub const LEVEL_TYPE_THREAD: u32 = 1;
    pub const LEVEL_TYPE_CORE: u32 = 2;
    pub mod ecx {
        pub const LEVEL_TYPE_SHIFT: u32 = 8; // Shift for setting level type for leaf 11
    }
}
