// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier,
};

/// T2S template
///
/// Mask CPUID to make exposed CPU features as close as possbile to AWS T2 instance and allow
/// migrating snapshots between hosts with Intel Skylake and Cascade Lake securely.
///
/// Reference:
/// - Intel SDM: https://cdrdv2.intel.com/v1/dl/getContent/671200
/// - CPUID Enumeration and Architectural MSRs: https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/cpuid-enumeration-and-architectural-msrs.html
#[allow(clippy::unusual_byte_groupings)]
pub fn t2s() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![
            CpuidLeafModifier {
                leaf: 0x1,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    // EAX: Version Information
                    // - Bits 03-00: Stepping ID.
                    // - Bits 07-04: Model.
                    // - Bits 11-08: Family.
                    // - Bits 13-12: Processor Type.
                    // - Bits 19-16: Extended Model ID.
                    // - Bits 27-20: Extended Family ID.
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_11111111_1111_00_11_1111_1111_1111,
                            value: 0b0000_00000000_0011_00_00_0110_1111_0010,
                        },
                    },
                    // ECX: Feature Information
                    // - Bit 02: DTES64
                    // - Bit 03: MONITOR
                    // - Bit 04: DS-CPL
                    // - Bit 05: VMX
                    // - Bit 06: SMX
                    // - Bit 07: EIST
                    // - Bit 08: TM2
                    // - Bit 10: CNXT-ID
                    // - Bit 11: SDBG
                    // - Bit 14: xTPR Update Control
                    // - Bit 15: PDCM
                    // - Bit 18: DCA
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0100_1100_1101_1111_1100,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX: Feature Information
                    // - Bit 07: MCE
                    // - Bit 12: MTRR
                    // - Bit 18: PSN
                    // - Bit 21: DS
                    // - Bit 22: ACPI
                    // - Bit 27: SS
                    // - Bit 29: TM
                    // - Bit 30: IA-64 (deprecated) https://www.intel.com/content/dam/www/public/us/en/documents/manuals/itanium-architecture-vol-4-manual.pdf
                    // - Bit 31: PBE
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b1110_1000_0110_0100_0001_0000_1000_0000,
                            value: 0b0000_0000_0000_0000_0001_0000_1000_0000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0x7,
                subleaf: 0x0,
                flags: KvmCpuidFlags(1),
                modifiers: vec![
                    // EBX:
                    // - Bit 02: SGX
                    // - Bit 04: HLE
                    // - Bit 09: Enhanced REP MOVSB/STOSB
                    // - Bit 11: RTM
                    // - Bit 12: RDT-M
                    // - Bit 14: MPX
                    // - Bit 15: RDT-A
                    // - Bit 16: AVX512F
                    // - Bit 17: AVX512DQ
                    // - Bit 18: RDSEED
                    // - Bit 19: ADX
                    // - Bit 21: AVX512_IFMA
                    // - Bit 22: PCOMMIT (deprecated) https://www.intel.com/content/www/us/en/developer/articles/technical/deprecate-pcommit-instruction.html
                    // - Bit 23: CLFLUSHOPT
                    // - Bit 24: CLWB
                    // - Bit 25: Intel Processor Trace
                    // - Bit 26: AVX512PF
                    // - Bit 27: AVX512ER
                    // - Bit 28: AVX512CD
                    // - Bit 29: SHA
                    // - Bit 30: AVX512BW
                    // - Bit 31: AVX512VL
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b1111_1111_1110_1111_1101_1010_0001_0100,
                            value: 0b0000_0000_0000_0000_0000_0010_0000_0000,
                        },
                    },
                    // ECX:
                    // - Bit 01: AVX512_VBMI
                    // - Bit 02: UMIP
                    // - Bit 03: PKU
                    // - Bit 04: OSPKE
                    // - Bit 06: AVX512_VBMI2
                    // - Bit 08: GFNI
                    // - Bit 09: VAES
                    // - Bit 10: VPCLMULQDQ
                    // - Bit 11: AVX512_VNNI
                    // - Bit 12: AVX512_BITALG
                    // - Bit 14: AVX512_VPOPCNTDQ
                    // - Bit 16: LA57
                    // - Bit 22: RDPID
                    // - Bit 30: SGX_LC
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0100_0000_0100_0001_0101_1111_0101_1110,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX:
                    // - Bit 02: AVX512_4VNNIW
                    // - Bit 03: AVX512_4FMAPS
                    // - Bit 04: Fast Short REP MOV
                    // - Bit 08: AVX512_VP2INTERSECT
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0000_0000_0001_0001_1100,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0xd,
                subleaf: 0x0,
                flags: KvmCpuidFlags(1),
                modifiers: vec![
                    // EAX:
                    // - Bits 04-03: MPX state
                    // - Bits 07-05: AVX-512 state
                    // - Bit 09: PKRU state
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0000_0000_00_1_0_111_11_000,
                            value: 0b0000_0000_0000_0000_0000_00_0_0_000_00_000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0xd,
                subleaf: 0x1,
                flags: KvmCpuidFlags(1),
                modifiers: vec![
                    // EAX:
                    // - Bit 01: Supports XSAVEC and the compacted form of XRSTOR
                    // - Bit 02: Supports XGETBV
                    // - Bit 03: Supports XSAVES/XRSTORS and IA32_XSS
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0000_0000_0000_0000_1110,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0x80000001,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    // ECX:
                    // - Bit 08: PREFETCHW
                    // - Bit 29: MONITORX and MWAITX
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0010_0000_0000_0000_0000_0001_0000_0000,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX:
                    // - Bit 26: 1-GByte pages
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0100_0000_0000_0000_0000_0000_0000,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                ],
            },
            CpuidLeafModifier {
                leaf: 0x80000008,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    // EBX:
                    // - Bit 09: WBNOINVD
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0000_0000_0010_0000_0000,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                ],
            },
        ],
        msr_modifiers: vec![
            // IA32_ARCH_CAPABILITIES:
            // - Bit 00: RDCL_NO
            // - Bit 01: IBRS_ALL
            // - Bit 02: RSBA
            // - Bit 03: SKIP_L1DFL_VMENTRY
            // - Bit 04: SSB_NO
            // - Bit 05: MDS_NO
            // - Bit 06: IF_PSCHANGE_MC_NO
            // - Bit 07: TSX_CTRL
            // - Bit 08: TAA_NO
            // - Bit 09: MCU_CONTROL
            // - Bit 10: MISC_PACKAGE_CTLS
            // - Bit 11: ENERGY_FILTERING_CTL
            // - Bit 12: DOITM
            // - Bit 13: SBDR_SSDP_NO
            // - Bit 14: FBSDP_NO
            // - Bit 15: PSDP_NO
            // - Bit 16: Reserved
            // - Bit 17: FB_CLEAR
            // - Bit 18: FB_CLEAR_CTRL
            // - Bit 19: RRSBA
            // - Bit 20: BHI_NO
            // - Bit 21: XAPIC_DISABLE_STATUS
            // - Bit 22: Reserved
            // - Bit 23: OVERCLOCKING_STATUS
            // - Bit 24: PBRSB_NO
            // - Bit 26: GDS_NO
            // - Bits 63-25: Reserved
            RegisterModifier {
            addr: 0x10a,
            bitmap: RegisterValueFilter {
                filter: 0b1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111,
                value: 0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0100_0000_1000_0000_1100_0100_1100,
            },
        }],
        ..Default::default()
    }
}
