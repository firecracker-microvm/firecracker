// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cpuid::cpuid_ffi::KvmCpuidFlags;
use crate::cpuid::{AmdCpuid, Cpuid, CpuidEntry, CpuidKey, CpuidRegisters};

/// This is translated from `cpuid -r` within a T2A guest microVM on an ec2 m6a.metal instance:
///
/// ```text
/// CPU 0:
///    0x00000000 0x00: eax=0x00000010 ebx=0x68747541 ecx=0x444d4163 edx=0x69746e65
///    0x00000001 0x00: eax=0x000306f2 ebx=0x00020800 ecx=0xfffa3203 edx=0x178bfbff
///    0x00000002 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000003 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000006 0x00: eax=0x00000004 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000007 0x00: eax=0x00000000 ebx=0x001007ab ecx=0x00000000 edx=0x8c000000
///    0x00000008 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000009 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000a 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000c 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000d 0x00: eax=0x00000007 ebx=0x00000340 ecx=0x00000988 edx=0x00000000
///    0x0000000d 0x01: eax=0x00000001 ebx=0x00000348 ecx=0x00000000 edx=0x00000000
///    0x0000000d 0x02: eax=0x00000100 ebx=0x00000240 ecx=0x00000000 edx=0x00000000
///    0x0000000e 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x0000000f 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x00000010 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x40000000 0x00: eax=0x40000001 ebx=0x4b4d564b ecx=0x564b4d56 edx=0x0000004d
///    0x40000001 0x00: eax=0x01007efb ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000000 0x00: eax=0x8000001f ebx=0x68747541 ecx=0x444d4163 edx=0x69746e65
///    0x80000001 0x00: eax=0x00a00f11 ebx=0x40000000 ecx=0x00c00237 edx=0x2813fbff
///    0x80000002 0x00: eax=0x20444d41 ebx=0x43595045 ecx=0x00000000 edx=0x00000000
///    0x80000003 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000004 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000005 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000006 0x00: eax=0x48002200 ebx=0x68004200 ecx=0x02006140 edx=0x06009140
///    0x80000007 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000100
///    0x80000008 0x00: eax=0x00003030 ebx=0x030ed000 ecx=0x00007001 edx=0x00000000
///    0x80000009 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000000a 0x00: eax=0x00000001 ebx=0x00000008 ecx=0x00000000 edx=0x00000009
///    0x8000000b 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000000c 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000000d 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000000e 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000000f 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000010 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000011 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000012 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000013 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000014 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000015 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000016 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000017 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000018 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x80000019 0x00: eax=0xf040f040 ebx=0xf0400000 ecx=0x00000000 edx=0x00000000
///    0x8000001a 0x00: eax=0x00000006 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000001b 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000001c 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000001d 0x00: eax=0x00000121 ebx=0x01c0003f ecx=0x0000003f edx=0x00000000
///    0x8000001d 0x01: eax=0x00000122 ebx=0x01c0003f ecx=0x0000003f edx=0x00000000
///    0x8000001d 0x02: eax=0x00000143 ebx=0x01c0003f ecx=0x000003ff edx=0x00000002
///    0x8000001d 0x03: eax=0x00004163 ebx=0x03c0003f ecx=0x00007fff edx=0x00000001
///    0x8000001e 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0x8000001f 0x00: eax=0x0101fd3f ebx=0x00004173 ecx=0x000001fd edx=0x000001fe
///    0x80860000 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
///    0xc0000000 0x00: eax=0x00000000 ebx=0x00000000 ecx=0x00000000 edx=0x00000000
/// ```
#[allow(clippy::too_many_lines)]
pub fn t2a() -> Cpuid {
    Cpuid::Amd(AmdCpuid({
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            CpuidKey {
                leaf: 0x0,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x10,
                    ebx: 0x68747541,
                    ecx: 0x444d4163,
                    edx: 0x69746e65,
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
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
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
                    edx: 0x8c000000,
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
                    ecx: 0x988,
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
                    ebx: 0x348,
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
                leaf: 0x10,
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
                    eax: 0x01007efb,
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
                    eax: 0x8000001f,
                    ebx: 0x68747541,
                    ecx: 0x444d4163,
                    edx: 0x69746e65,
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
                    eax: 0xa00f11,
                    ebx: 0x40000000,
                    ecx: 0xc00237,
                    edx: 0x2813fbff,
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
                    eax: 0x20444d41,
                    ebx: 0x43595045,
                    ecx: 0x0,
                    edx: 0x0,
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
                    eax: 0x0,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
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
                    eax: 0x0,
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
                    eax: 0x48002200,
                    ebx: 0x68004200,
                    ecx: 0x2006140,
                    edx: 0x6009140,
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
                    eax: 0x3030,
                    ebx: 0x30ed000,
                    ecx: 0x7001,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x80000009,
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
                leaf: 0xc000000a,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x1,
                    ebx: 0x8,
                    ecx: 0x0,
                    edx: 0x9,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000000b,
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
                leaf: 0x8000000c,
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
                leaf: 0x8000000d,
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
                leaf: 0x8000000e,
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
                leaf: 0x8000000f,
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
                leaf: 0x80000010,
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
                leaf: 0x80000011,
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
                leaf: 0x80000012,
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
                leaf: 0x80000013,
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
                leaf: 0x80000014,
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
                leaf: 0x80000015,
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
                leaf: 0x80000016,
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
                leaf: 0x80000017,
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
                leaf: 0x80000018,
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
                leaf: 0x80000019,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0xf040f040,
                    ebx: 0xf0400000,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001a,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x6,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001b,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x6,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001c,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x6,
                    ebx: 0x0,
                    ecx: 0x0,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001d,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x121,
                    ebx: 0x1c0003f,
                    ecx: 0x3f,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001d,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x121,
                    ebx: 0x1c0003f,
                    ecx: 0x3f,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001d,
                subleaf: 0x1,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x122,
                    ebx: 0x1c0003f,
                    ecx: 0x3f,
                    edx: 0x0,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001d,
                subleaf: 0x2,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x143,
                    ebx: 0x1c0003f,
                    ecx: 0x3ff,
                    edx: 0x2,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001d,
                subleaf: 0x3,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x1),
                result: CpuidRegisters {
                    eax: 0x4163,
                    ebx: 0x3c0003f,
                    ecx: 0x7fff,
                    edx: 0x1,
                },
            },
        );
        map.insert(
            CpuidKey {
                leaf: 0x8000001e,
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
                leaf: 0x8000001f,
                subleaf: 0x0,
            },
            CpuidEntry {
                flags: KvmCpuidFlags(0x0),
                result: CpuidRegisters {
                    eax: 0x101fd3f,
                    ebx: 0x4173,
                    ecx: 0x1fd,
                    edx: 0x1fe,
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
