// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier,
};

/// T2A template
///
/// Provide instruction set feature partity with Intel Cascade Lake or later using T2CL template.
///
/// References:
/// - Intel SDM: <https://cdrdv2.intel.com/v1/dl/getContent/671200>
/// - AMD APM: <https://www.amd.com/system/files/TechDocs/40332.pdf>
/// - CPUID Enumeration and Architectural MSRs: <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/cpuid-enumeration-and-architectural-msrs.html>
#[allow(clippy::unusual_byte_groupings)]
pub fn t2a() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![
            CpuidLeafModifier {
                leaf: 0x1,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    // EAX: Version Information
                    // - Bits 03-00: Stepping (AMD APM) / Stepping ID (Intel SDM)
                    // - Bits 07-04: BaseModel (AMD APM) / Model (Intel SDM)
                    // - Bits 11-08: BaseFamily (AMD APM) / Family (Intel SDM)
                    // - Bits 13-12: Reserved (AMD APM) / Processor Type (Intel SDM)
                    // - Bits 19-16: ExtModel (AMD APM) / Extended Model ID (Intel SDM)
                    // - Bits 27-20: ExtFamily (AMD APM) / Extended Family ID (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_11111111_1111_00_11_1111_1111_1111,
                            value: 0b0000_00000000_0011_00_00_0110_1111_0010,
                        },
                    },
                    // ECX: Feature Information
                    // - Bit 02: Reserved (AMD APM) / DTES64 (Intel SDM)
                    // - Bit 03: MONITOR (AMD APM) / MONITOR (Intel SDM)
                    // - Bit 04: Reserved (AMD APM) / DS-CPL (Intel SDM)
                    // - Bit 05: Reserved (AMD APM) / VMX (Intel SDM)
                    // - Bit 06: Reserved (AMD APM) / SMX (Intel SDM)
                    // - Bit 07: Reserved (AMD APM) / EIST (Intel SDM)
                    // - Bit 08: Reserved (AMD APM) / TM2 (Intel SDM)
                    // - Bit 10: Reserved (AMD APM) / CNXT-ID (Intel SDM)
                    // - Bit 11: Reserved (AMD APM) / SDBG (Intel SDM)
                    // - Bit 14: Reserved (AMD APM) / xTPR Update Control (Intel SDM)
                    // - Bit 15: Reserved (AMD APM) / PDCM (Intel SDM)
                    // - Bit 18: Reserevd (AMD APM) / DCA (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0100_1100_1101_1111_1100,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX: Feature Information
                    // - Bit 07: MCE (AMD APM) / MCE (Intel SDM)
                    // - Bit 12: MTRR (AMD APM) / MTRR (Intel SDM)
                    // - Bit 18: Reserved (AMD APM) / PSN (Intel SDM)
                    // - Bit 21: Reserved (AMD APM) / DS (Intel SDM)
                    // - Bit 22: Reserved (AMD APM) / ACPI (Intel SDM)
                    // - Bit 27: Reserved (AMD APM) / SS (Intel SDM)
                    // - Bit 29: Reserved (AMD APM) / TM (Intel SDM)
                    // - Bit 30: Reserved (AMD APM) / IA-64 (deprecated) https://www.intel.com/content/dam/www/public/us/en/documents/manuals/itanium-architecture-vol-4-manual.pdf
                    // - Bit 31: Reserved (AMD APM) / PBE (Intel SDM)
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
                    // - Bit 02: Reserved (AMD APM) / SGX (Intel SDM)
                    // - Bit 04: Reserved (AMD APM) / HLE (Intel SDM)
                    // - Bit 09: Reserved (AMD APM) / Enhanced REP MOVSB/STOSB (Intel SDM)
                    // - Bit 11: Reserved (AMD APM) / RTM (Intel SDM)
                    // - Bit 12: PQM (AMD APM) / RDT-M (Intel SDM)
                    // - Bit 14: Reserved (AMD APM) / MPX (Intel SDM)
                    // - Bit 15: PQE (AMD APM) / RDT-A (Intel SDM)
                    // - Bit 16: Reserved (AMD APM) / AVX512F (Intel SDM)
                    // - Bit 17: Reserved (AMD APM) / AVX512DQ (Intel SDM)
                    // - Bit 18: RDSEED (AMD APM) / RDSEED (Intel SDM)
                    // - Bit 19: ADX (AMD APM) / ADX (Intel SDM)
                    // - Bit 21: Reserved (AMD APM) / AVX512_IFMA (Intel SDM)
                    // - Bit 22: RDPID (AMD APM) / Reserved (Intel SDM)
                    //   On kernel codebase and Intel SDM, RDPID is enumerated at CPUID.07h:ECX.RDPID[bit 22].
                    //   https://elixir.bootlin.com/linux/v6.3.8/source/arch/x86/include/asm/cpufeatures.h#L389
                    // - Bit 23: CLFLUSHOPT (AMD APM) / CLFLUSHOPT (Intel SDM)
                    // - Bit 24: CLWB (AMD APM) / CLWB (Intel SDM)
                    // - Bit 25: Reserved (AMD APM) / Intel Processor Trace (Intel SDM)
                    // - Bit 26: Reserved (AMD APM) / AVX512PF (Intel SDM)
                    // - Bit 27: Reserved (AMD APM) / AVX512ER (Intel SDM)
                    // - Bit 28: Reserved (AMD APM) / AVX512CD (Intel SDM)
                    // - Bit 29: SHA (AMD APM) / SHA (Intel SDM)
                    // - Bit 30: Reserved (AMD APM) / AVX512BW (Intel SDM)
                    // - Bit 31: Reserved (AMD APM) / AVX512VL (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b1111_1111_1110_1111_1101_1010_0001_0100,
                            value: 0b0000_0000_0000_0000_0000_0010_0000_0000,
                        },
                    },
                    // ECX:
                    // - Bit 01: Reserved (AMD APM) / AVX512_VBMI (Intel SDM)
                    // - Bit 02: UMIP (AMD APM) / UMIP (Intel SDM)
                    // - Bit 03: PKU (AMD APM) / PKU (Intel SDM)
                    // - Bit 04: OSPKE (AMD APM) / OSPKE (Intel SDM)
                    // - Bit 06: Reserved (AMD APM) / AVX512_VBMI2 (Intel SDM)
                    // - Bit 08: Reserved (AMD APM) / GFNI (Intel SDM)
                    // - Bit 09: VAES (AMD APM) / VAES (Intel SDM)
                    // - Bit 10: VPCLMULQDQ (AMD APM) / VPCLMULQDQ (Intel SDM)
                    // - Bit 11: Reserved (AMD APM) / AVX512_VNNI (Intel SDM)
                    // - Bit 12: Reserved (AMD APM) / AVX512_BITALG (Intel SDM)
                    // - Bit 14: Reserved (AMD APM) / AVX512_VPOPCNTDQ (Intel SDM)
                    // - Bit 16: LA57 (AMD APM) / LA57 (Intel SDM)
                    // - Bit 22: Reserved (AMD APM) / RDPID and IA32_TSC_AUX (Intel SDM)
                    // - Bit 30: Reserved (AMD APM) / SGX_LC (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0100_0000_0100_0001_0101_1111_0101_1110,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX:
                    // - Bit 02: Reserved (AMD APM) / AVX512_4VNNIW (Intel SDM)
                    // - Bit 03: Reserved (AMD APM) / AVX512_4FMAPS (Intel SDM)
                    // - Bit 04: Reserved (AMD APM) / Fast Short REP MOV (Intel SDM)
                    // - Bit 08: Reserved (AMD APM) / AVX512_VP2INTERSECT (Intel SDM)
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
                    // - Bits 04-03: Reserved (AMD APM) / MPX state (Intel SDM)
                    // - Bits 07-05: Reserved (AMD APM) / AVX-512 state (Intel SDM)
                    // - Bit 09: MPK (AMD APM) / PKRU state (Intel SDM)
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
                    // - Bit 01: XSAVEC (AMD APM) / Supports XSAVEC and the compacted form of
                    //   XRSTOR (Intel SDM)
                    // - Bit 02: XGETBV (AMD APM) / Supports XGETBV (Intel SDM)
                    // - Bit 03: XSAVES (AMD APM) / Supports XSAVES/XRSTORS and IA32_XSS (Intel
                    //   SDM)
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
                    // - Bit 02: SVM (AMD APM) / Reserved (Intel SDM)
                    // - Bit 06: SSE4A (AMD APM) / Reserved (Intel SDM)
                    // - Bit 07: MisAlignSse (AMD APM) / Reserved (Intel SDM)
                    // - Bit 08: 3DNowPrefetch (AMD APM) / PREFETCHW (Intel SDM)
                    // - Bit 29: MONITORX (AMD APM) / MONITORX and MWAITX (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0010_0000_0000_0000_0000_0001_1100_0100,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX:
                    // - Bit 22: MmxExt (AMD APM) / Reserved (Intel SDM)
                    // - Bit 25: FFXSR (AMD APM) / Reserved (Intel SDM)
                    // - Bit 26: Page1GB (AMD APM) / 1-GByte pages (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0110_0100_0000_0000_0000_0000_0000,
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
                    // - Bit 00: CLZERO (AMD APM) / Reserved (Intel SDM)
                    // - Bit 02: RstrFpErrPtrs (AMD APM) / Reserved (Intel SDM)
                    // - Bit 09: WBNOINVD (AMD APM) / WBNOINVD (Intel SDM)
                    // - Bit 18: IbrsPreferred (ADM APM) / Reserved (Intel SDm)
                    // - Bit 19: IbrsSameMode (AMD APM) / Reserved (Intel SDM)
                    // - Bit 20: EferLmsleUnsupported (AMD APM) / Reserved (Intel SDM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0001_1100_0000_0010_0000_0101,
                            value: 0b0000_0000_0001_1100_0000_0000_0000_0100,
                        },
                    },
                ],
            },
        ],
        msr_modifiers: vec![],
        ..Default::default()
    }
}
