// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::kvm_msr_entry;

use crate::arch::x86_64::msr::ArchCapaMSRFlags;
use crate::arch_gen::x86::msr_index::MSR_IA32_ARCH_CAPABILITIES;
use crate::cpuid::cpuid_ffi::KvmCpuidFlags;
use crate::cpuid::{Cpuid, CpuidEntry, CpuidKey, CpuidRegisters, IntelCpuid};

/// Add the MSR entries specific to this T2S template.
#[inline]
pub fn update_t2cl_msr_entries(msr_entries: &mut Vec<kvm_msr_entry>) {
    let capabilities = ArchCapaMSRFlags::RDCL_NO
        | ArchCapaMSRFlags::IBRS_ALL
        | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
        | ArchCapaMSRFlags::MDS_NO
        | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
        | ArchCapaMSRFlags::TSX_CTRL;
    msr_entries.push(kvm_msr_entry {
        index: MSR_IA32_ARCH_CAPABILITIES,
        data: capabilities.bits(),
        ..kvm_msr_entry::default()
    });
}

/// This is translated from `cpuid -r` within a T2CL guest microVM on an ec2 m5.metal instance:
///
/// ```text
/// CPU 0:
///    0x00000000 0x00: eax=0x00000016 ebx=0x756e6547 ecx=0x6c65746e edx=0x49656e69
///    0x00000001 0x00: eax=0x000306f2 ebx=0x00020800 ecx=0xfffa3203 edx=0x178bfbff
///    0x00000002 0x00: eax=0x76036301 ebx=0x00f0b5ff ecx=0x00000000 edx=0x00c30000
///    0x00000003 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000004 0x00: eax=0x04000121 ebx=0x01c0003f ecx=0x0000003f edx=0x00000000
///    0x00000004 0x01: eax=0x04000122 ebx=0x01c0003f ecx=0x0000003f edx=0x00000000
///    0x00000004 0x02: eax=0x04000143 ebx=0x03c0003f ecx=0x000003ff edx=0x00000000
///    0x00000004 0x03: eax=0x04004163 ebx=0x0280003f ecx=0x0000bfff edx=0x00000004
///    0x00000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000006 0x00: eax=0x00000004 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000007 0x00: eax=0x00000000 ebx=0x001007ab ecx=0x00000000 edx=0xac000400
///    0x00000008 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000009 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000a 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000b 0x00: eax=0x00000000 ebx=0x00000001 ecx=0x00000100 edx=0x00000000
///    0x0000000b 0x01: eax=0x00000007 ebx=0x00000002 ecx=0x00000201 edx=0x00000000
///    0x0000000c 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000d 0x00: eax=0x00000007 ebx=0x00000340 ecx=0x00000a88 edx=0x00000000
///    0x0000000d 0x01: eax=0x00000001 ebx=0x00000a08 ecx=0x00000000 edx=0x00000000
///    0x0000000d 0x02: eax=0x00000100 ebx=0x00000240 ecx=0x00000000 edx=0x00000000
///    0x0000000e 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000f 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000010 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000011 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000012 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000013 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000014 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000015 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000016 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x40000000 0x00: eax=0x40000001 ebx=0x4b4d564b ecx=0x564b4d56 edx=0x0000004d
///    0x40000001 0x00: eax=0x01007efb ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000000 0x00: eax=0x80000008 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000001 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000021 edx=0x28100800
///    0x80000002 0x00: eax=0x65746e49 ebx=0x2952286c ecx=0x6f655820 edx=0x2952286e
///    0x80000003 0x00: eax=0x6f725020 ebx=0x73736563 ecx=0x4020726f edx=0x352e3220
///    0x80000004 0x00: eax=0x7a484730 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000006 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x01006040 edx=0x00000000
///    0x80000007 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000100
///    0x80000008 0x00: eax=0x0000302e ebx=0x0100d000 ecx=0x00000000 edx=0x00000000
///    0x80860000 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0xc0000000 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
/// ```
#[allow(clippy::too_many_lines)]
pub fn t2cl() -> Cpuid {
    Cpuid::Intel(IntelCpuid({
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            CpuidKey {
                leaf: 0x0,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0xd,
                    ebx: 0x756e6547,
                    ecx: 0x6c65746e,
                    edx: 0x49656e69,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x1,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x306f2,
                    ebx: 0x20800,
                    ecx: 0xfffa3203,
                    edx: 0x178bfbff,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x2,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x76036301,
                    ebx: 0xf0b5ff,
                    ecx: 0x0,
                    edx: 0xc30000,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x3,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x4,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x4000121,
                    ebx: 0x1c0003f,
                    ecx: 0x3f,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x4,
                subleaf: 0x1,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x4000122,
                    ebx: 0x1c0003f,
                    ecx: 0x3f,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x4,
                subleaf: 0x2,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x4000143,
                    ebx: 0x3c0003f,
                    ecx: 0x3ff,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x4,
                subleaf: 0x3,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x4004163,
                    ebx: 0x280003f,
                    ecx: 0xbfff,
                    edx: 0x4,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x5,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x6,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x4,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x7,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x1007ab,
                    ecx: 0x0,
                    edx: 0xac000400,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x9,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xa,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xb,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x1,
                    ecx: 0x100,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xb,
                subleaf: 0x1,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x7,
                    ebx: 0x2,
                    ecx: 0x201,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xb,
                subleaf: 0x2,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x2,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xc,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xd,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x7,
                    ebx: 0x340,
                    ecx: 0xa88,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xd,
                subleaf: 0x1,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x1,
                    ebx: 0xa08,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xd,
                subleaf: 0x2,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x100,
                    ebx: 0x240,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xe,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xf,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x10,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x11,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x12,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x13,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x14,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x15,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x16,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x40000000,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x40000001,
                    ebx: 0x4b4d564b,
                    ecx: 0x564b4d56,
                    edx: 0x4d,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x40000001,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x1007efb,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000000,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x80000008,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000001,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x21,
                    edx: 0x28100800,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000002,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x65746e49,
                    ebx: 0x2952286c,
                    ecx: 0x6f655820,
                    edx: 0x2952286e,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000003,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x6f725020,
                    ebx: 0x73736563,
                    ecx: 0x4020726f,
                    edx: 0x352e3220,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000004,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x7a484730,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000005,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000006,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x1006040,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000007,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x100,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000008,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x302e,
                    ebx: 0x100d000,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80860000,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0xc0000000,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map
    }))
}
