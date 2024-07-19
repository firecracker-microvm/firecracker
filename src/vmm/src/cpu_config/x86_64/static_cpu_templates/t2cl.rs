// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, RegisterModifier,
};

/// T2CL template
///
/// Mask CPUID to make exposed CPU features as close as possbile to Intel Cascade Lake and provide
/// instruction set feature partity with AMD Milan using T2A template.
///
/// References:
/// - Intel SDM: <https://cdrdv2.intel.com/v1/dl/getContent/671200>
/// - AMD APM: <https://www.amd.com/system/files/TechDocs/40332.pdf>
/// - CPUID Enumeration and Architectural MSRs: <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/cpuid-enumeration-and-architectural-msrs.html>
#[allow(clippy::unusual_byte_groupings)]
pub fn t2cl() -> CustomCpuTemplate {
    CustomCpuTemplate {
        cpuid_modifiers: vec![
            CpuidLeafModifier {
                leaf: 0x1,
                subleaf: 0x0,
                flags: KvmCpuidFlags(0),
                modifiers: vec![
                    // EAX: Version Information
                    // - Bits 03-00: Stepping ID (Intel SDM) / Stepping (AMD APM)
                    // - Bits 07-04: Model (Intel SDM) / BaseModel (AMD APM)
                    // - Bits 11-08: Family (Intel SDM) / BaseFamily (AMD APM)
                    // - Bits 13-12: Processor Type (Intel SDM) / Reserved (AMD APM)
                    // - Bits 19-16: Extended Model ID (Intel SDM) / ExtModel (AMD APM)
                    // - Bits 27-20: Extended Family ID (Intel SDM) / ExtFamily (AMD APM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Eax,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_11111111_1111_00_11_1111_1111_1111,
                            value: 0b0000_00000000_0011_00_00_0110_1111_0010,
                        },
                    },
                    // ECX: Feature Information
                    // - Bit 02: DTES64 (Intel SDM) / Reserved (AMD APM)
                    // - Bit 03: MONITOR (Intel SDM) / MONITOR (AMD APM)
                    // - Bit 04: DS-CPL (Intel SDM) / Reserved (AMD APM)
                    // - Bit 05: VMX (Intel SDM) / Reserved (AMD APM)
                    // - Bit 06: SMX (Intel SDM) / Reserved (AMD APM)
                    // - Bit 07: EIST (Intel SDM) / Reserved (AMD APM)
                    // - Bit 08: TM2 (Intel SDM) / Reserved (AMD APM)
                    // - Bit 10: CNXT-ID (Intel SDM) / Reserved (AMD APM)
                    // - Bit 11: SDBG (Intel SDM) / Reserved (AMD APM)
                    // - Bit 14: xTPR Update Control (Intel SDM) / Reserved (AMD APM)
                    // - Bit 15: PDCM (Intel SDM) / Reserved (AMD APM)
                    // - Bit 18: DCA (Intel SDM) / Reserevd (AMD APM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0000_0000_0100_1100_1101_1111_1100,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX: Feature Information
                    // - Bit 07: MCE (Intel SDM) / MCE (AMD APM)
                    // - Bit 12: MTRR (Intel SDM) / MTRR (AMD APM)
                    // - Bit 18: PSN (Intel SDM) / Reserved (AMD APM)
                    // - Bit 21: DS (Intel SDM) / Reserved (AMD APM)PC
                    // - Bit 22: ACPI (Intel SDM) / Reserved (AMD APM)
                    // - Bit 27: SS (Intel SDM) / Reserved (AMD APM)
                    // - Bit 29: TM (Intel SDM) / Reserved (AMD APM)
                    // - Bit 30: IA64 (deprecated) / Reserved (AMD APM) https://www.intel.com/content/dam/www/public/us/en/documents/manuals/itanium-architecture-vol-4-manual.pdf
                    // - Bit 31: PBE (Intel SDM) / Reserved (AMD APM)
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
                    // - Bit 02: SGX (Intel SDM) / Reserved (AMD APM)
                    // - Bit 04: HLE (Intel SDM) / Reserved (AMD APM)
                    // - Bit 09: Enhanced REP MOVSB/STOSB (Intel SDM) / Reserved (AMD APM)
                    // - Bit 11: RTM (Intel SDM) / Reserved (AMD APM)
                    // - Bit 12: RDT-M (Intel SDM) / PQM (AMD APM)
                    // - Bit 14: MPX (Intel SDM) / Reserved (AMD APM)
                    // - Bit 15: RDT-A (Intel SDM) / PQE (AMD APM)
                    // - Bit 16: AVX512F (Intel SDM) / Reserved (AMD APM)
                    // - Bit 17: AVX512DQ (Intel SDM) / Reserved (AMD APM)
                    // - Bit 18: RDSEED (Intel SDM) / RDSEED (AMD APM)
                    // - Bit 19: ADX (Intel SDM) / ADX (AMD APM)
                    // - Bit 21: AVX512_IFMA (Intel SDM) / Reserved (AMD APM)
                    // - Bit 22: Reserved (Intel SDM) / RDPID (AMD APM)
                    //   On kernel codebase and Intel SDM, RDPID is enumerated at CPUID.07h:ECX.RDPID[bit 22].
                    //   https://elixir.bootlin.com/linux/v6.3.8/source/arch/x86/include/asm/cpufeatures.h#L389
                    // - Bit 23: CLFLUSHOPT (Intel SDM) / CLFLUSHOPT (AMD APM)
                    // - Bit 24: CLWB (Intel SDM) / CLWB (AMD APM)
                    // - Bit 25: Intel Processor Trace (Intel SDM) / Reserved (AMD APM)
                    // - Bit 26: AVX512PF (Intel SDM) / Reserved (AMD APM)
                    // - Bit 27: AVX512ER (Intel SDM) / Reserved (AMD APM)
                    // - Bit 28: AVX512CD (Intel SDM) / Reserved (AMD APM)
                    // - Bit 29: SHA (Intel SDM) / SHA (AMD APM)
                    // - Bit 30: AVX512BW (Intel SDM) / Reserved (AMD APM)
                    // - Bit 31: AVX512VL (Intel SDM) / Reserved (AMD APM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ebx,
                        bitmap: RegisterValueFilter {
                            filter: 0b1111_1111_1110_1111_1101_1010_0001_0100,
                            value: 0b0000_0000_0000_0000_0000_0010_0000_0000,
                        },
                    },
                    // ECX:
                    // - Bit 01: AVX512_VBMI (Intel SDM) / Reserved (AMD APM)
                    // - Bit 02: UMIP (Intel SDM) / UMIP (AMD APM)
                    // - Bit 03: PKU (Intel SDM) / PKU (AMD APM)
                    // - Bit 04: OSPKE (Intel SDM) / OSPKE (AMD APM)
                    // - Bit 06: AVX512_VBMI2 (Intel SDM) / Reserved (AMD APM)
                    // - Bit 08: GFNI (Intel SDM) / Reserved (AMD APM)
                    // - Bit 09: VAES (Intel SDM) / VAES (AMD APM)
                    // - Bit 10: VPCLMULQDQ (Intel SDM) / VPCLMULQDQ (AMD APM)
                    // - Bit 11: AVX512_VNNI (Intel SDM) / Reserved (AMD APM)
                    // - Bit 12: AVX512_BITALG (Intel SDM) / Reserved (AMD APM)
                    // - Bit 14: AVX512_VPOPCNTDQ (Intel SDM) / Reserved (AMD APM)
                    // - Bit 16: LA57 (Intel SDM) / LA57 (AMD APM)
                    // - Bit 22: RDPID and IA32_TSC_AUX (Intel SDM) / Reserved (AMD APM)
                    // - Bit 30: SGX_LC (Intel SDM) / Reserved (AMD APM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0100_0000_0100_0001_0101_1111_0101_1110,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX:
                    // - Bit 02: AVX512_4VNNIW (Intel SDM) / Reserved (AMD APM)
                    // - Bit 03: AVX512_4FMAPS (Intel SDM) / Reserved (AMD APM)
                    // - Bit 04: Fast Short REP MOV (Intel SDM) / Reserved (AMD APM)
                    // - Bit 08: AVX512_VP2INTERSECT (Intel SDM) / Reserved (AMD APM)
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
                    // - Bits 04-03: MPX state (Intel SDM) / Reserved (AMD APM)
                    // - Bits 07-05: AVX-512 state (Intel SDM) / Reserved (AMD APM)
                    // - Bit 09: PKRU state (Intel SDM) / MPK (AMD APM)
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
                    // - Bit 01: Supports XSAVEC and the compacted form of XRSTOR (Intel SDM) /
                    //   XSAVEC (AMD APM)
                    // - Bit 02: Supports XGETBV (Intel SDM) / XGETBV (AMD APM)
                    // - Bit 03: Supports XSAVES/XRSTORS and IA32_XSS (Intel SDM) / XSAVES (AMD
                    //   APM)
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
                    // - Bit 06: Reserved (Intel SDM) / SSE4A (AMD APM)
                    // - Bit 07: Reserved (Intel SDM) / MisAlignSse (AMD APM)
                    // - Bit 08: PREFETCHW (Intel SDM) / 3DNowPrefetch (AMD APM)
                    // - Bit 29: MONITORX and MWAITX (Intel SDM) / MONITORX (AMD APM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Ecx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0010_0000_0000_0000_0000_0001_1100_0000,
                            value: 0b0000_0000_0000_0000_0000_0000_0000_0000,
                        },
                    },
                    // EDX:
                    // - Bit 22: Reserved (Intel SDM) / MmxExt (AMD APM)
                    // - Bit 23: Reserved (Intel SDM) / MMX (AMD APM)
                    // - Bit 24: Reserved (Intel SDM) / FSXR (AMD APM)
                    // - Bit 25: Reserved (Intel SDM) / FFXSR (AMD APM)
                    // - Bit 26: 1-GByte pages (Intel SDM) / Page1GB (AMD APM)
                    CpuidRegisterModifier {
                        register: CpuidRegister::Edx,
                        bitmap: RegisterValueFilter {
                            filter: 0b0000_0111_1100_0000_0000_0000_0000_0000,
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
                    // - Bit 09: WBNOINVD (Intel SDM) / WBNOINVD (AMD APM)
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
            // - Bit 09: MCU_CONTROL
            // - Bit 10: MISC_PACKAGE_CTLS
            // - Bit 11: ENERGY_FILTERING_CTL
            // - Bit 12: DOITM
            // - Bit 16: Reserved
            // - Bit 18: FB_CLEAR_CTRL
            // - Bit 20: BHI_NO
            // - Bit 21: XAPIC_DISABLE_STATUS
            // - Bit 22: Reserved
            // - Bit 23: OVERCLOCKING_STATUS
            // - Bit 25: GDS_CTRL
            // - Bits 63-27: Reserved (Intel SDM)
            //
            // As T2CL template does not aim to provide an ability to migrate securely guests across
            // different processors, there is no need to mask hardware security mitigation bits off
            // only to make it appear to the guest as if it's running on the most vulnerable of the
            // supported processors. Guests might be able to benefit from performance improvements
            // by making the most use of available mitigations on the processor. Thus, T2CL template
            // passes through security mitigation bits that KVM thinks are able to be passed
            // through. The list of such bits are found in the following link.
            // https://elixir.bootlin.com/linux/v6.8.2/source/arch/x86/kvm/x86.c#L1621
            // - Bit 00: RDCL_NO
            // - Bit 01: IBRS_ALL
            // - Bit 02: RSBA
            // - Bit 03: SKIP_L1DFL_VMENTRY
            // - Bit 04: SSB_NO
            // - Bit 05: MDS_NO
            // - Bit 06: IF_PSCHANGE_MC_NO
            // - Bit 07: TSX_CTRL
            // - Bit 08: TAA_NO
            // - Bit 13: SBDR_SSDP_NO
            // - Bit 14: FBSDP_NO
            // - Bit 15: PSDP_NO
            // - Bit 17: FB_CLEAR
            // - Bit 19: RRSBA
            // - Bit 24: PBRSB_NO
            // - Bit 26: GDS_NO
            // - Bit 27: RFDS_NO
            // - Bit 28: RFDS_CLEAR
            //
            // Note that this MSR is specific to Intel processors.
            RegisterModifier {
                addr: 0x10a,
                bitmap: RegisterValueFilter {
                    filter: 0b1111_1111_1111_1111_1111_1111_1111_1111_1110_0010_1111_0101_0001_1110_0000_0000,
                    value: 0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                },
            },
        ],
        ..Default::default()
    }
}
