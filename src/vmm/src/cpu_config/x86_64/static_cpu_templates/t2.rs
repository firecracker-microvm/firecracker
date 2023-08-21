// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpu_config::templates::{CustomCpuTemplate, RegisterValueFilter};
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier,
};

/// T2 template
///
/// Mask CPUID to make exposed CPU features as close as possbile to AWS T2 instance.
///
/// CPUID dump taken in t2.micro on 2023-06-15:
/// =====
/// $ cpuid -1 -r
/// Disclaimer: cpuid may not support decoding of all cpuid registers.
/// CPU:
///    0x00000000 0x00: eax=0x0000000d ebx=0x756e6547 ecx=0x6c65746e edx=0x49656e69
///    0x00000001 0x00: eax=0x000306f2 ebx=0x00010800 ecx=0xfffa3203 edx=0x178bfbff
///    0x00000002 0x00: eax=0x76036301 ebx=0x00f0b5ff ecx=0x00000000 edx=0x00c10000
///    0x00000003 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000004 0x00: eax=0x00004121 ebx=0x01c0003f ecx=0x0000003f edx=0x00000000
///    0x00000004 0x01: eax=0x00004122 ebx=0x01c0003f ecx=0x0000003f edx=0x00000000
///    0x00000004 0x02: eax=0x00004143 ebx=0x01c0003f ecx=0x000001ff edx=0x00000000
///    0x00000004 0x03: eax=0x0007c163 ebx=0x04c0003f ecx=0x00005fff edx=0x00000006
///    0x00000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000006 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000007 0x00: eax=0x00000000 ebx=0x000007a9 ecx=0x00000000 edx=0x00000000
///    0x00000008 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000009 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000a 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000b 0x00: eax=0x00000001 ebx=0x00000001 ecx=0x00000100 edx=0x00000000
///    0x0000000b 0x01: eax=0x00000005 ebx=0x00000001 ecx=0x00000201 edx=0x00000000
///    0x0000000c 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000d 0x00: eax=0x00000007 ebx=0x00000340 ecx=0x00000340 edx=0x00000000
///    0x0000000d 0x01: eax=0x00000001 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000d 0x02: eax=0x00000100 ebx=0x00000240 ecx=0x00000000 edx=0x00000000
///    0x40000000 0x00: eax=0x40000005 ebx=0x566e6558 ecx=0x65584d4d edx=0x4d4d566e
///    0x40000001 0x00: eax=0x0004000b ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x40000002 0x00: eax=0x00000001 ebx=0x40000000 ecx=0x00000000 edx=0x00000000
///    0x40000003 0x00: eax=0x00000006 ebx=0x00000002 ecx=0x00249f0a edx=0x00000001
///    0x40000003 0x02: eax=0x9b842c23 ebx=0x007c8980 ecx=0xd5551b14 edx=0xffffffff
///    0x40000004 0x00: eax=0x0000001c ebx=0x00000000 ecx=0x0000762b edx=0x00000000
///    0x40000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000000 0x00: eax=0x80000008 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000001 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000021 edx=0x28100800
///    0x80000002 0x00: eax=0x65746e49 ebx=0x2952286c ecx=0x6f655820 edx=0x2952286e
///    0x80000003 0x00: eax=0x55504320 ebx=0x2d354520 ecx=0x36373632 edx=0x20337620
///    0x80000004 0x00: eax=0x2e322040 ebx=0x48473034 ecx=0x0000007a edx=0x00000000
///    0x80000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000006 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x01006040 edx=0x00000000
///    0x80000007 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000008 0x00: eax=0x0000302e ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80860000 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0xc0000000 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
/// =====
///
/// References:
/// - Intel SDM: https://cdrdv2.intel.com/v1/dl/getContent/671200
#[allow(clippy::unusual_byte_groupings)]
pub fn t2() -> CustomCpuTemplate {
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
        msr_modifiers: vec![],
        ..Default::default()
    }
}
