// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::module_name_repetitions)]
use std::default::Default;
use std::fmt;

#[cfg(feature = "static")]
use arrayvec::ArrayVec;
use log_derive::{logfn, logfn_inputs};
use serde::{Deserialize, Serialize};

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::{cascade_cpo, RawCpuidEntry};

#[allow(clippy::non_ascii_literal)]
static KEYWORDS: phf::Map<u8, &'static str> = phf::phf_map! {
    0x00u8 => "Null descriptor, this byte contains no information",
    0x01u8 => "Instruction TLB: 4 KByte pages, 4-way set associative, 32 entries",
    0x02u8 => "Instruction TLB: 4 MByte pages, fully associative, 2 entries",
    0x03u8 => "Data TLB: 4 KByte pages, 4-way set associative, 64 entries",
    0x04u8 => "Data TLB: 4 MByte pages, 4-way set associative, 8 entries",
    0x05u8 => "Data TLB1: 4 MByte pages, 4-way set associative, 32 entries",
    0x06u8 => "1st-level instruction cache: 8 KBytes, 4-way set associative, 32 byte line size",
    0x08u8 => "1st-level instruction cache: 16 KBytes, 4-way set associative, 32 byte line size",
    0x09u8 => "1st-level instruction cache: 32KBytes, 4-way set associative, 64 byte line size",
    0x0Au8 => "1st-level data cache: 8 KBytes, 2-way set associative, 32 byte line size",
    0x0Bu8 => "Instruction TLB: 4 MByte pages, 4-way set associative, 4 entries",
    0x0Cu8 => "1st-level data cache: 16 KBytes, 4-way set associative, 32 byte line size",
    0x0Du8 => "1st-level data cache: 16 KBytes, 4-way set associative, 64 byte line size",
    0x0Eu8 => "1st-level data cache: 24 KBytes, 6-way set associative, 64 byte line size",
    0x1Du8 => "2nd-level cache: 128 KBytes, 2-way set associative, 64 byte line size",
    0x21u8 => "2nd-level cache: 256 KBytes, 8-way set associative, 64 byte line size",
    0x22u8 => "3rd-level cache: 512 KBytes, 4-way set associative, 64 byte line size, 2 lines per sector",
    0x23u8 => "3rd-level cache: 1 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x24u8 => "2nd-level cache: 1 MBytes, 16-way set associative, 64 byte line size",
    0x25u8 => "3rd-level cache: 2 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x29u8 => "3rd-level cache: 4 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x2Cu8 => "1st-level data cache: 32 KBytes, 8-way set associative, 64 byte line size",
    0x30u8 => "1st-level instruction cache: 32 KBytes, 8-way set associative, 64 byte line size",
    0x40u8 => "No 2nd-level cache or, if processor contains a valid 2nd-level cache, no 3rd-level cache",
    0x41u8 => "2nd-level cache: 128 KBytes, 4-way set associative, 32 byte line size",
    0x42u8 => "2nd-level cache: 256 KBytes, 4-way set associative, 32 byte line size",
    0x43u8 => "2nd-level cache: 512 KBytes, 4-way set associative, 32 byte line size",
    0x44u8 => "2nd-level cache: 1 MByte, 4-way set associative, 32 byte line size",
    0x45u8 => "2nd-level cache: 2 MByte, 4-way set associative, 32 byte line size",
    0x46u8 => "3rd-level cache: 4 MByte, 4-way set associative, 64 byte line size",
    0x47u8 => "3rd-level cache: 8 MByte, 8-way set associative, 64 byte line size",
    0x48u8 => "2nd-level cache: 3MByte, 12-way set associative, 64 byte line size",
    0x49u8 => "3rd-level cache: 4MB, 16-way set associative, 64-byte line size (Intel Xeon processor MP, Family 0FH, Model 06H);\n2nd-level cache: 4 MByte, 16-way set associative, 64 byte line size",
    0x4Au8 => "3rd-level cache: 6MByte, 12-way set associative, 64 byte line size",
    0x4Bu8 => "3rd-level cache: 8MByte, 16-way set associative, 64 byte line size",
    0x4Cu8 => "3rd-level cache: 12MByte, 12-way set associative, 64 byte line size",
    0x4Du8 => "3rd-level cache: 16MByte, 16-way set associative, 64 byte line size",
    0x4Eu8 => "2nd-level cache: 6MByte, 24-way set associative, 64 byte line size",
    0x4Fu8 => "Instruction TLB: 4 KByte pages, 32 entries",
    0x50u8 => "Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 64 entries",
    0x51u8 => "Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 128 entries",
    0x52u8 => "Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 256 entries",
    0x55u8 => "Instruction TLB: 2-MByte or 4-MByte pages, fully associative, 7 entries",
    0x56u8 => "Data TLB0: 4 MByte pages, 4-way set associative, 16 entries",
    0x57u8 => "Data TLB0: 4 KByte pages, 4-way associative, 16 entries",
    0x59u8 => "Data TLB0: 4 KByte pages, fully associative, 16 entries",
    0x5Au8 => "Data TLB0: 2 MByte or 4 MByte pages, 4-way set associative, 32 entries",
    0x5Bu8 => "Data TLB: 4 KByte and 4 MByte pages, 64 entries",
    0x5Cu8 => "Data TLB: 4 KByte and 4 MByte pages, 128 entries",
    0x5Du8 => "Data TLB: 4 KByte and 4 MByte pages, 256 entries",
    0x60u8 => "1st-level data cache: 16 KByte, 8-way set associative, 64 byte line size",
    0x61u8 => "Instruction TLB: 4 KByte pages, fully associative, 48 entries",
    0x63u8 => "Data TLB: 2 MByte or 4 MByte pages, 4-way set associative, 32 entries and a separate array with 1 GByte pages, 4-way set associative, 4 entries",
    0x64u8 => "Data TLB: 4 KByte pages, 4-way set associative, 512 entries",
    0x66u8 => "1st-level data cache: 8 KByte, 4-way set associative, 64 byte line size",
    0x67u8 => "1st-level data cache: 16 KByte, 4-way set associative, 64 byte line size",
    0x68u8 => "1st-level data cache: 32 KByte, 4-way set associative, 64 byte line size",
    0x6Au8 => "uTLB: 4 KByte pages, 8-way set associative, 64 entries",
    0x6Bu8 => "DTLB: 4 KByte pages, 8-way set associative, 256 entries",
    0x6Cu8 => "DTLB: 2M/4M pages, 8-way set associative, 128 entries",
    0x6Du8 => "DTLB: 1 GByte pages, fully associative, 16 entries",
    0x70u8 => "Trace cache: 12 K-μop, 8-way set associative",
    0x71u8 => "Trace cache: 16 K-μop, 8-way set associative",
    0x72u8 => "Trace cache: 32 K-μop, 8-way set associative",
    0x76u8 => "Instruction TLB: 2M/4M pages, fully associative, 8 entries",
    0x78u8 => "2nd-level cache: 1 MByte, 4-way set associative, 64byte line size",
    0x79u8 => "2nd-level cache: 128 KByte, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x7Au8 => "2nd-level cache: 256 KByte, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x7Bu8 => "2nd-level cache: 512 KByte, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x7Cu8 => "2nd-level cache: 1 MByte, 8-way set associative, 64 byte line size, 2 lines per sector",
    0x7Du8 => "2nd-level cache: 2 MByte, 8-way set associative, 64byte line size",
    0x7Fu8 => "2nd-level cache: 512 KByte, 2-way set associative, 64-byte line size",
    0x80u8 => "2nd-level cache: 512 KByte, 8-way set associative, 64-byte line size",
    0x82u8 => "2nd-level cache: 256 KByte, 8-way set associative, 32 byte line size",
    0x83u8 => "2nd-level cache: 512 KByte, 8-way set associative, 32 byte line size",
    0x84u8 => "2nd-level cache: 1 MByte, 8-way set associative, 32 byte line size",
    0x85u8 => "2nd-level cache: 2 MByte, 8-way set associative, 32 byte line size",
    0x86u8 => "2nd-level cache: 512 KByte, 4-way set associative, 64 byte line size",
    0x87u8 => "2nd-level cache: 1 MByte, 8-way set associative, 64 byte line size",
    0xA0u8 => "DTLB: 4k pages, fully associative, 32 entries",
    0xB0u8 => "Instruction TLB: 4 KByte pages, 4-way set associative, 128 entries",
    0xB1u8 => "Instruction TLB: 2M pages, 4-way, 8 entries or 4M pages, 4-way, 4 entries",
    0xB2u8 => "Instruction TLB: 4KByte pages, 4-way set associative, 64 entries",
    0xB3u8 => "Data TLB: 4 KByte pages, 4-way set associative, 128 entries",
    0xB4u8 => "Data TLB1: 4 KByte pages, 4-way associative, 256 entries",
    0xB5u8 => "Instruction TLB: 4KByte pages, 8-way set associative, 64 entries",
    0xB6u8 => "Instruction TLB: 4KByte pages, 8-way set associative, 128 entries",
    0xBAu8 => "Data TLB1: 4 KByte pages, 4-way associative, 64 entries",
    0xC0u8 => "Data TLB: 4 KByte and 4 MByte pages, 4-way associative, 8 entries",
    0xC1u8 => "Shared 2nd-Level TLB: 4 KByte / 2 MByte pages, 8-way associative, 1024 entries",
    0xC2u8 => "DTLB: 4 KByte/2 MByte pages, 4-way associative, 16 entries",
    0xC3u8 => "Shared 2nd-Level TLB: 4 KByte / 2 MByte pages, 6-way associative, 1536 entries. Also 1GBbyte pages, 4-way, 16 entries.",
    0xC4u8 => "DTLB: 2M/4M Byte pages, 4-way associative, 32 entries",
    0xCAu8 => "Shared 2nd-Level TLB: 4 KByte pages, 4-way associative, 512 entries",
    0xD0u8 => "3rd-level cache: 512 KByte, 4-way set associative, 64 byte line size",
    0xD1u8 => "3rd-level cache: 1 MByte, 4-way set associative, 64 byte line size",
    0xD2u8 => "3rd-level cache: 2 MByte, 4-way set associative, 64 byte line size",
    0xD6u8 => "3rd-level cache: 1 MByte, 8-way set associative, 64 byte line size",
    0xD7u8 => "3rd-level cache: 2 MByte, 8-way set associative, 64 byte line size",
    0xD8u8 => "3rd-level cache: 4 MByte, 8-way set associative, 64 byte line size",
    0xDCu8 => "3rd-level cache: 1.5 MByte, 12-way set associative, 64 byte line size",
    0xDDu8 => "3rd-level cache: 3 MByte, 12-way set associative, 64 byte line size",
    0xDEu8 => "3rd-level cache: 6 MByte, 12-way set associative, 64 byte line size",
    0xE2u8 => "3rd-level cache: 2 MByte, 16-way set associative, 64 byte line size",
    0xE3u8 => "3rd-level cache: 4 MByte, 16-way set associative, 64 byte line size",
    0xE4u8 => "3rd-level cache: 8 MByte, 16-way set associative, 64 byte line size",
    0xEAu8 => "3rd-level cache: 12MByte, 24-way set associative, 64 byte line size",
    0xEBu8 => "3rd-level cache: 18MByte, 24-way set associative, 64 byte line size",
    0xECu8 => "3rd-level cache: 24MByte, 24-way set associative, 64 byte line size",
    0xF0u8 => "64-Byte prefetching",
    0xF1u8 => "128-Byte prefetching",
    0xFEu8 => "CPUID leaf 2 does not report TLB descriptor information; use CPUID leaf 18H to query TLB and other address translation parameters.",
    0xFFu8 => "CPUID leaf 2 does not report cache descriptor information, use CPUID leaf 4 to query cache parameters"
};
impl fmt::Display for Leaf2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a: [&'static str; 16] = self.into();
        write!(f, "{:#?}", a)
    }
}
// - The least-significant-byte of eax always returns 01h.
// - The most significant bit indicates whether the register contains valid information (TODO Does
//   this mean we only have 3 descriptors per register?)
impl From<&Leaf2> for [&'static str; 16] {
    fn from(this: &Leaf2) -> Self {
        [
            KEYWORDS.get(&this.0.eax[0]).unwrap(),
            KEYWORDS.get(&this.0.eax[1]).unwrap(),
            KEYWORDS.get(&this.0.eax[2]).unwrap(),
            KEYWORDS.get(&this.0.eax[3]).unwrap(),
            KEYWORDS.get(&this.0.ebx[0]).unwrap(),
            KEYWORDS.get(&this.0.ebx[1]).unwrap(),
            KEYWORDS.get(&this.0.ebx[2]).unwrap(),
            KEYWORDS.get(&this.0.ebx[3]).unwrap(),
            KEYWORDS.get(&this.0.ecx[0]).unwrap(),
            KEYWORDS.get(&this.0.ecx[1]).unwrap(),
            KEYWORDS.get(&this.0.ecx[2]).unwrap(),
            KEYWORDS.get(&this.0.ecx[3]).unwrap(),
            KEYWORDS.get(&this.0.edx[0]).unwrap(),
            KEYWORDS.get(&this.0.edx[1]).unwrap(),
            KEYWORDS.get(&this.0.edx[2]).unwrap(),
            KEYWORDS.get(&this.0.edx[3]).unwrap(),
        ]
    }
}
impl From<(u32, u32, u32, u32)> for Leaf2 {
    fn from((eax, ebx, ecx, edx): (u32, u32, u32, u32)) -> Self {
        Self(Leaf {
            eax: eax.to_ne_bytes(),
            ebx: ebx.to_ne_bytes(),
            ecx: ecx.to_ne_bytes(),
            edx: edx.to_ne_bytes(),
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Leaf types
// -------------------------------------------------------------------------------------------------
/// A generic leaf formed of 4 members `eax`, `ebx`, `ecx` and `edx`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf<A, B, C, D> {
    /// EAX register.
    pub eax: A,
    /// EBX register.
    pub ebx: B,
    /// ECX register.
    pub ecx: C,
    /// EDX register.
    pub edx: D,
}
impl<A, B, C, D> From<(A, B, C, D)> for Leaf<A, B, C, D> {
    fn from((a, b, c, d): (A, B, C, D)) -> Self {
        Leaf {
            eax: a,
            ebx: b,
            ecx: c,
            edx: d,
        }
    }
}
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::CpuidResult;
#[cfg(target_arch = "x86_64")]
impl<A: From<u32>, B: From<u32>, C: From<u32>, D: From<u32>> From<CpuidResult>
    for Leaf<A, B, C, D>
{
    fn from(CpuidResult { eax, ebx, ecx, edx }: CpuidResult) -> Self {
        Leaf {
            eax: A::from(eax),
            ebx: B::from(ebx),
            ecx: C::from(ecx),
            edx: D::from(edx),
        }
    }
}
impl<A: From<u32>, B: From<u32>, C: From<u32>, D: From<u32>> From<&RawCpuidEntry>
    for Leaf<A, B, C, D>
{
    fn from(
        &RawCpuidEntry {
            eax, ebx, ecx, edx, ..
        }: &RawCpuidEntry,
    ) -> Self {
        Leaf {
            eax: A::from(eax),
            ebx: B::from(ebx),
            ecx: C::from(ecx),
            edx: D::from(edx),
        }
    }
}

/// Leaf 00H
pub type Leaf0 = Leaf<u32, FixedString<4>, FixedString<4>, FixedString<4>>;
/// Leaf 01H
pub type Leaf1 = Leaf<Leaf1Eax, Leaf1Ebx, Leaf1Ecx, Leaf1Edx>;
/// Leaf 02H
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf2(pub Leaf<[u8; 4], [u8; 4], [u8; 4], [u8; 4]>);
/// Leaf 03H
pub type Leaf3 = Leaf<Leaf3Eax, Leaf3Ebx, Leaf3Ecx, Leaf3Edx>;
/// Leaf 04H wrapper
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf4(
    #[cfg(feature = "static")] pub ArrayVec<Leaf4Subleaf, 8>,
    #[cfg(not(feature = "static"))] pub Vec<Leaf4Subleaf>,
);
/// Leaf 04H
pub type Leaf4Subleaf = Leaf<Leaf4Eax, Leaf4Ebx, Leaf4Ecx, Leaf4Edx>;
/// Leaf 05H
pub type Leaf5 = Leaf<Leaf5Eax, Leaf5Ebx, Leaf5Ecx, Leaf5Edx>;
/// Leaf 06H
pub type Leaf6 = Leaf<Leaf6Eax, Leaf6Ebx, Leaf6Ecx, Leaf6Edx>;
/// Leaf 07H
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf7(pub Leaf7Subleaf0, pub Option<Leaf7Subleaf1>);
/// Leaf 07H subleaf 0
pub type Leaf7Subleaf0 =
    Leaf<Leaf7Subleaf0Eax, Leaf7Subleaf0Ebx, Leaf7Subleaf0Ecx, Leaf7Subleaf0Edx>;
/// Leaf 07H subleaf 1
pub type Leaf7Subleaf1 =
    Leaf<Leaf7Subleaf1Eax, Leaf7Subleaf1Ebx, Leaf7Subleaf1Ecx, Leaf7Subleaf1Edx>;
/// Leaf 09H
pub type Leaf9 = Leaf<Leaf9Eax, Leaf9Ebx, Leaf9Ecx, Leaf9Edx>;
/// Leaf 0AH
pub type LeafA = Leaf<LeafAEax, LeafAEbx, LeafAEcx, LeafAEdx>;
/// Leaf 0BH wrapper
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct LeafB(
    #[cfg(feature = "static")] pub ArrayVec<LeafBSubleaf, 4>,
    #[cfg(not(feature = "static"))] pub Vec<LeafBSubleaf>,
);
/// Leaf 0BH
pub type LeafBSubleaf = Leaf<LeafBEax, LeafBEbx, LeafBEcx, LeafBEdx>;
/// Leaf 0DH
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct LeafD(
    pub LeafDSubleaf0,
    pub LeafDSubleaf1,
    #[cfg(feature = "static")] pub ArrayVec<LeafDSubleafGt1, 16>,
    #[cfg(not(feature = "static"))] pub Vec<LeafDSubleafGt1>,
);
/// Leaf 0DH subleaf 0
pub type LeafDSubleaf0 =
    Leaf<LeafDSubleaf0Eax, LeafDSubleaf0Ebx, LeafDSubleaf0Ecx, LeafDSubleaf0Edx>;
/// Leaf 0DH subleaf 1
pub type LeafDSubleaf1 =
    Leaf<LeafDSubleaf1Eax, LeafDSubleaf1Ebx, LeafDSubleaf1Ecx, LeafDSubleaf1Edx>;
/// Leaf 0DH subleaf >1
pub type LeafDSubleafGt1 =
    Leaf<LeafDSubleafGt1Eax, LeafDSubleafGt1Ebx, LeafDSubleafGt1Ecx, LeafDSubleafGt1Edx>;
/// Leaf 0FH
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct LeafF(pub LeafFSubleaf0, pub Option<LeafFSubleaf1>);
/// Leaf 0FH subleaf 0
pub type LeafFSubleaf0 =
    Leaf<LeafFSubleaf0Eax, LeafFSubleaf0Ebx, LeafFSubleaf0Ecx, LeafFSubleaf0Edx>;
/// Leaf 0FH subleaf 1
pub type LeafFSubleaf1 =
    Leaf<LeafFSubleaf1Eax, LeafFSubleaf1Ebx, LeafFSubleaf1Ecx, LeafFSubleaf1Edx>;
/// Leaf 10H
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf10(
    pub Leaf10Subleaf0,
    pub Option<Leaf10Subleaf1>,
    pub Option<Leaf10Subleaf2>,
    pub Option<Leaf10Subleaf3>,
);
/// Leaf 10H subleaf 0
pub type Leaf10Subleaf0 =
    Leaf<Leaf10Subleaf0Eax, Leaf10Subleaf0Ebx, Leaf10Subleaf0Ecx, Leaf10Subleaf0Edx>;
/// Leaf 10H subleaf 1
pub type Leaf10Subleaf1 =
    Leaf<Leaf10Subleaf1Eax, Leaf10Subleaf1Ebx, Leaf10Subleaf1Ecx, Leaf10Subleaf1Edx>;
/// Leaf 10H subleaf 2
pub type Leaf10Subleaf2 =
    Leaf<Leaf10Subleaf2Eax, Leaf10Subleaf2Ebx, Leaf10Subleaf2Ecx, Leaf10Subleaf2Edx>;
/// Leaf 10H subleaf 3
pub type Leaf10Subleaf3 =
    Leaf<Leaf10Subleaf3Eax, Leaf10Subleaf3Ebx, Leaf10Subleaf3Ecx, Leaf10Subleaf3Edx>;
/// Leaf 12H
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf12(
    pub Leaf12Subleaf0,
    pub Leaf12Subleaf1,
    #[cfg(feature = "static")] pub ArrayVec<Leaf12SubleafGt1, 100>,
    #[cfg(not(feature = "static"))] pub Vec<Leaf12SubleafGt1>,
);
/// Leaf 12 subleaf 0
pub type Leaf12Subleaf0 =
    Leaf<Leaf12Subleaf0Eax, Leaf12Subleaf0Ebx, Leaf12Subleaf0Ecx, Leaf12Subleaf0Edx>;
/// Leaf 12H subleaf 1
pub type Leaf12Subleaf1 =
    Leaf<Leaf12Subleaf1Eax, Leaf12Subleaf1Ebx, Leaf12Subleaf1Ecx, Leaf12Subleaf1Edx>;
/// Leaf 12H subleaf >1
pub type Leaf12SubleafGt1 =
    Leaf<Leaf12SubleafGt1Eax, Leaf12SubleafGt1Ebx, Leaf12SubleafGt1Ecx, Leaf12SubleafGt1Edx>;
/// Leaf 14H
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf14(pub Leaf14Subleaf0, pub Option<Leaf14Subleaf1>);
/// Leaf 14H subleaf 0
pub type Leaf14Subleaf0 =
    Leaf<Leaf14Subleaf0Eax, Leaf14Subleaf0Ebx, Leaf14Subleaf0Ecx, Leaf14Subleaf0Edx>;
/// Leaf 14H subleaf 1
pub type Leaf14Subleaf1 =
    Leaf<Leaf14Subleaf1Eax, Leaf14Subleaf1Ebx, Leaf14Subleaf1Ecx, Leaf14Subleaf1Edx>;
/// Leaf 15H
pub type Leaf15 = Leaf<Leaf15Eax, Leaf15Ebx, Leaf15Ecx, Leaf15Edx>;
/// Leaf 16H
pub type Leaf16 = Leaf<Leaf16Eax, Leaf16Ebx, Leaf16Ecx, Leaf16Edx>;
/// Leaf 17H
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf17(
    pub Leaf17Subleaf0,
    pub Leaf17Subleaf1,
    pub Leaf17Subleaf2,
    pub Leaf17Subleaf3,
);
/// Leaf 17H subleaf 0
pub type Leaf17Subleaf0 =
    Leaf<Leaf17Subleaf0Eax, Leaf17Subleaf0Ebx, Leaf17Subleaf0Ecx, Leaf17Subleaf0Edx>;
/// Leaf 17H subleaf 1
pub type Leaf17Subleaf1 =
    Leaf<Leaf17Subleaf1Eax, Leaf17Subleaf1Ebx, Leaf17Subleaf1Ecx, Leaf17Subleaf1Edx>;
/// Leaf 17H subleaf 2
pub type Leaf17Subleaf2 = Leaf17Subleaf1;
/// Leaf 17H subleaf 3
pub type Leaf17Subleaf3 = Leaf17Subleaf1;
/// Leaf 18H
#[cfg(feature = "leaf_18")]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf18(
    pub Leaf18Subleaf0,
    #[cfg(feature = "static")] pub ArrayVec<Leaf18SubleafGt0, 4000>,
    #[cfg(not(feature = "static"))] pub Vec<Leaf18SubleafGt0>,
);
/// Leaf 18H subleaf 0
#[cfg(feature = "leaf_18")]
pub type Leaf18Subleaf0 =
    Leaf<Leaf18Subleaf0Eax, Leaf18Subleaf0Ebx, Leaf18Subleaf0Ecx, Leaf18Subleaf0Edx>;
/// Leaf 18H subleaf >0
#[cfg(feature = "leaf_18")]
pub type Leaf18SubleafGt0 =
    Leaf<Leaf18SubleafGt0Eax, Leaf18SubleafGt0Ebx, Leaf18SubleafGt0Ecx, Leaf18SubleafGt0Edx>;
/// Leaf 19H
pub type Leaf19 = Leaf<Leaf19Eax, Leaf19Ebx, Leaf19Ecx, Leaf19Edx>;
/// Leaf 1AH
pub type Leaf1A = Leaf<Leaf1AEax, Leaf1AEbx, Leaf1AEcx, Leaf1AEdx>;
// TODO I need to investigate the layout of this leaf
/// Leaf 1BH
pub type Leaf1B = Leaf<Leaf1BEax, Leaf1BEbx, Leaf1BEcx, Leaf1BEdx>;
/// Leaf 1CH
pub type Leaf1C = Leaf<Leaf1CEax, Leaf1CEbx, Leaf1CEcx, Leaf1CEdx>;
/// Leaf 1FH wrapper
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Leaf1F(
    #[cfg(feature = "static")] pub ArrayVec<Leaf1FSubleaf, 0>,
    #[cfg(not(feature = "static"))] pub Vec<Leaf1FSubleaf>,
);
/// Leaf 1FH
pub type Leaf1FSubleaf = Leaf<Leaf1FEax, Leaf1FEbx, Leaf1FEcx, Leaf1FEdx>;
// TODO I need to investigate the layout of this leaf
/// Leaf 20H
pub type Leaf20 = Leaf<Leaf20Eax, Leaf20Ebx, Leaf20Ecx, Leaf20Edx>;
/// Leaf 80000000H
pub type Leaf80000000 = Leaf<Leaf80000000Eax, Leaf80000000Ebx, Leaf80000000Ecx, Leaf80000000Edx>;
/// Leaf 80000001H
pub type Leaf80000001 = Leaf<Leaf80000001Eax, Leaf80000001Ebx, Leaf80000001Ecx, Leaf80000001Edx>;
/// Leaf 80000002H
pub type Leaf80000002 = Leaf<Leaf80000002Eax, Leaf80000002Ebx, Leaf80000002Ecx, Leaf80000002Edx>;
/// Leaf 80000003H
pub type Leaf80000003 = Leaf80000002;
/// Leaf 80000004H
pub type Leaf80000004 = Leaf80000002;
/// Leaf 80000005H
pub type Leaf80000005 = Leaf<Leaf80000005Eax, Leaf80000005Ebx, Leaf80000005Ecx, Leaf80000005Edx>;
/// Leaf 80000006H
pub type Leaf80000006 = Leaf<Leaf80000006Eax, Leaf80000006Ebx, Leaf80000006Ecx, Leaf80000006Edx>;
/// Leaf 80000007H
pub type Leaf80000007 = Leaf<Leaf80000007Eax, Leaf80000007Ebx, Leaf80000007Ecx, Leaf80000007Edx>;
/// Leaf 80000008H
pub type Leaf80000008 = Leaf<Leaf80000008Eax, Leaf80000008Ebx, Leaf80000008Ecx, Leaf80000008Edx>;
// -------------------------------------------------------------------------------------------------
// Supports
// -------------------------------------------------------------------------------------------------
/// Logs a warning depending on which registers where not fully checked within a leaf.
macro_rules! warn_support {
    ($a:literal, $eax:literal, $ebx:literal, $ecx:literal, $edx:literal) => {
        if let Some(msg) = support_warn($eax, $ebx, $ecx, $edx) {
            log::info!(
                "Could not fully validate support for Intel CPUID leaf {} due to being unable to \
             fully compare register/s: {}.",
                $a,
                msg
            );
        }
    };
}
/// Returns a static string depending the register boolean.
#[allow(clippy::fn_params_excessive_bools)]
const fn support_warn(eax: bool, ebx: bool, ecx: bool, edx: bool) -> Option<&'static str> {
    match (eax, ebx, ecx, edx) {
        (true, true, true, true) => None,
        (false, true, true, true) => Some("EAX"),
        (true, false, true, true) => Some("EBX"),
        (true, true, false, true) => Some("ECX"),
        (true, true, true, false) => Some("EDX"),
        (false, false, true, true) => Some("EAX and EBX"),
        (false, true, false, true) => Some("EAX and ECX"),
        (false, true, true, false) => Some("EAX and EDX"),
        (true, false, false, true) => Some("EBX and ECX"),
        (true, false, true, false) => Some("EBX and EDX"),
        (true, true, false, false) => Some("ECX and EDX"),
        (false, false, false, true) => Some("EAX, EBX and ECX"),
        (false, false, true, false) => Some("EAX, EBX and EDX"),
        (false, true, false, false) => Some("EAX, ECX and EDX"),
        (true, false, false, false) => Some("EBX, ECX and EDX"),
        (false, false, false, false) => Some("EAX, EBX, ECX and EDX"),
    }
}

use crate::{FeatureComparison, FeatureRelation};

impl FeatureComparison for Leaf0 {
    /// We check the manufacturer id e.g. 'GenuineIntel' is an exact match and that
    /// 'Maximum Input Value for Basic CPUID Information.' is >=
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x0", true, true, true, true);
        if self.ebx == other.ebx && self.ecx == other.ecx && self.edx == other.edx {
            Some(self.eax.cmp(&other.eax).into())
        } else {
            None
        }
    }
}
impl FeatureComparison for Leaf1 {
    /// We check ECX and EDX are supersets and 'CLFLUSH line size' >= and
    /// 'Maximum number of addressable IDs for logical processors in this physical package' >=
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x1", false, false, true, true);
        let a = self
            .ebx
            .clflush
            .partial_cmp(&other.ebx.clflush)
            .map(FeatureRelation::from);
        log::info!("a: {:?}", a);

        let b = self
            .ebx
            .max_addressable_logical_processor_ids
            .partial_cmp(&other.ebx.max_addressable_logical_processor_ids)
            .map(FeatureRelation::from);
        log::info!("b: {:?}", b);

        // We ignore `tsc_deadline` and `osxs` by setting them both to 0 in `self` and `other`.
        let mask = {
            let mut temp = Leaf1Ecx::from(0);
            temp.tsc_deadline.on();
            temp.osxsave.on();
            !temp
        };

        let c = (self.ecx & mask)
            .cmp_flags(&(other.ecx & mask))
            .map(FeatureRelation::from);
        log::info!("c1:\n{}", self.ecx);
        log::info!("c2:\n{}", other.ecx);
        log::info!("c: {:?}", c);

        // We ignore `htt` by setting it to 0 in `self` and `other`.
        let mask = {
            let mut temp = Leaf1Edx::from(0);
            temp.htt.on();
            !temp
        };
        let d = (self.edx & mask)
            .cmp_flags(&(other.edx & mask))
            .map(FeatureRelation::from);
        log::info!("d1:\n{}", self.edx);
        log::info!("d2:\n{}", other.edx);
        log::info!("d: {:?}", d);

        let e = cascade_cpo!(a, b, c, d);
        log::info!("e: {:?}", e);
        e
    }
}
impl FeatureComparison for Leaf5 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x5", true, true, true, false);
        // Since we care `<=` here `Ordering::Less` corresponds to `Ordering::Greater` for
        // support, thus we reverse.
        let a = self
            .eax
            .smallest_monitor_line_size
            .partial_cmp(&other.eax.smallest_monitor_line_size)
            .map(std::cmp::Ordering::reverse)
            .map(FeatureRelation::from);
        log::info!("a: {:?}", a);
        let b = self
            .ebx
            .largest_monitor_line_size
            .partial_cmp(&other.ebx.largest_monitor_line_size)
            .map(FeatureRelation::from);
        log::info!("b: {:?}", b);
        let c = self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from);
        log::info!("c: {:?}", c);

        let d = cascade_cpo!(a, b, c);
        log::info!("d: {:?}", d);
        d
    }
}
impl FeatureComparison for Leaf6 {
    /// We do not currently check EDX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x6", true, true, true, false);
        cascade_cpo!(
            self.eax.cmp_flags(&other.eax).map(FeatureRelation::from),
            self.ebx
                .number_of_interrupt_thresholds_in_digital_thermal_sensor
                .partial_cmp(
                    &other
                        .ebx
                        .number_of_interrupt_thresholds_in_digital_thermal_sensor
                )
                .map(FeatureRelation::from),
            self.ecx
                .intel_thread_director_classes
                .partial_cmp(&other.ecx.intel_thread_director_classes)
                .map(FeatureRelation::from),
            self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from)
        )
    }
}
impl FeatureComparison for Leaf7 {
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        cpo(self.0.feature_cmp(&other.0), self.1.feature_cmp(&other.1))
    }
}
impl FeatureComparison for Leaf7Subleaf0 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        debug_assert!(
            self.eax.max_input_value_subleaf == 1 || self.eax.max_input_value_subleaf == 0
        );
        debug_assert!(
            other.eax.max_input_value_subleaf == 1 || other.eax.max_input_value_subleaf == 0
        );
        warn_support!("0x7 sub-leaf 0", true, true, true, true);
        cascade_cpo!(
            self.eax
                .max_input_value_subleaf
                .partial_cmp(&other.eax.max_input_value_subleaf)
                .map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from),
            self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from),
            self.edx.cmp_flags(&other.edx).map(FeatureRelation::from)
        )
    }
}
impl FeatureComparison for Leaf7Subleaf1 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x7 sub-leaf 1", true, true, true, true);
        cpo(
            self.eax.cmp_flags(&other.eax).map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from),
        )
    }
}
impl FeatureComparison for LeafA {
    /// We do not currently check EAX, ECX and EDX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0xA", false, true, false, false);
        self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from)
    }
}
impl FeatureComparison for LeafF {
    /// We check sub-leaves 0 and 1.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        cpo(self.0.feature_cmp(&other.0), self.1.feature_cmp(&other.1))
    }
}
impl FeatureComparison for LeafFSubleaf0 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0xF sub-leaf 0", true, true, true, true);
        cpo(
            self.ebx
                .max_rmid_range
                .partial_cmp(&other.ebx.max_rmid_range)
                .map(FeatureRelation::from),
            self.edx.cmp_flags(&other.edx).map(FeatureRelation::from),
        )
    }
}
impl FeatureComparison for LeafFSubleaf1 {
    /// We do not check EBX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0xF sub-leaf 1", true, false, true, true);
        cpo(
            self.ecx
                .rmid_max
                .partial_cmp(&other.ecx.rmid_max)
                .map(FeatureRelation::from),
            self.edx.cmp_flags(&other.edx).map(FeatureRelation::from),
        )
    }
}
impl FeatureComparison for Leaf10 {
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x10 due to being unable to \
             validate sub-leaf 2."
        );
        cascade_cpo!(
            self.0.feature_cmp(&other.0),
            self.1.feature_cmp(&other.1),
            self.3.feature_cmp(&other.3)
        )
    }
}
impl FeatureComparison for Leaf10Subleaf0 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x10 sub-leaf 0", true, true, true, true);
        self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from)
    }
}
impl FeatureComparison for Leaf10Subleaf1 {
    /// We only check ECX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x10 sub-leaf 1", false, false, true, false);
        self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from)
    }
}
impl FeatureComparison for Leaf10Subleaf3 {
    /// We only check ECX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x10 sub-leaf 3", false, false, true, false);
        self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from)
    }
}
impl FeatureComparison for Leaf14 {
    /// Only checks subleaf 1.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x14 due to being unable to \
             validate sub-leaf 1."
        );
        self.0.feature_cmp(&other.0)
    }
}
impl FeatureComparison for Leaf14Subleaf0 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x14 sub-leaf 0", true, true, true, true);
        cascade_cpo!(
            self.eax
                .max_subleaf
                .partial_cmp(&other.eax.max_subleaf)
                .map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from),
            self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from)
        )
    }
}
#[cfg(feature = "leaf_18")]
impl FeatureComparison for Leaf18 {
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x18 due to being unable to \
             validate sub-leaf 1."
        );
        self.0.feature_cmp(&other.0)
    }
}
#[cfg(feature = "leaf_18")]
impl FeatureComparison for Leaf18Subleaf0 {
    /// We do not check ECX or EDX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x18 sub-leaf 0", true, true, false, false);
        cascade_cpo!(
            self.eax
                .max_subleaf
                .partial_cmp(&other.eax.max_subleaf)
                .map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from)
        )
    }
}
impl FeatureComparison for Leaf19 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x19", true, true, true, true);
        cascade_cpo!(
            self.eax.cmp_flags(&other.eax).map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from),
            self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from)
        )
    }
}
impl FeatureComparison for Leaf1C {
    /// We do not check EAX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x1C", true, true, true, true);
        cascade_cpo!(
            self.eax.cmp_flags(&other.eax).map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from),
            self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from)
        )
    }
}
impl FeatureComparison for Leaf20 {
    /// We do not check EBX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        debug_assert_eq!(self.eax.max_subleaves, 1);
        debug_assert_eq!(other.eax.max_subleaves, 1);
        warn_support!("0x20", true, true, true, true);
        cpo(
            self.eax
                .max_subleaves
                .partial_cmp(&other.eax.max_subleaves)
                .map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from),
        )
    }
}
impl FeatureComparison for Leaf80000000 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x80000000", true, true, true, true);
        self.eax
            .max_extend_function_input
            .partial_cmp(&other.eax.max_extend_function_input)
            .map(FeatureRelation::from)
    }
}
impl FeatureComparison for Leaf80000001 {
    /// We do not check EAX.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x80000001", true, true, true, true);
        cpo(
            self.ecx.cmp_flags(&other.ecx).map(FeatureRelation::from),
            self.edx.cmp_flags(&other.edx).map(FeatureRelation::from),
        )
    }
}
impl FeatureComparison for Leaf80000007 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x80000007", true, true, true, true);
        self.edx.cmp_flags(&other.edx).map(FeatureRelation::from)
    }
}
impl FeatureComparison for Leaf80000008 {
    /// We check everything here.
    #[logfn(Info)]
    #[logfn_inputs(Info)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        warn_support!("0x80000008", true, true, true, true);
        cascade_cpo!(
            self.eax
                .physical_address_bits
                .partial_cmp(&other.eax.physical_address_bits)
                .map(FeatureRelation::from),
            self.eax
                .linear_address_bits
                .partial_cmp(&other.eax.linear_address_bits)
                .map(FeatureRelation::from),
            self.ebx.cmp_flags(&other.ebx).map(FeatureRelation::from)
        )
    }
}

// -------------------------------------------------------------------------------------------------
// Util & Tests
// -------------------------------------------------------------------------------------------------

/// Returns true if all 1 bits in `b` are also 1s in `a`.
pub fn superset_u32<T: Into<u32>>(a: T, b: T) -> bool {
    let (x, y): (u32, u32) = (a.into(), b.into());
    ((!x) & y) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn superset_u32_1() {
        assert!(superset_u32(0b1010_0101_u32, 0b0010_0101_u32));
    }
    #[test]
    fn superset_u32_2() {
        assert!(!superset_u32(0b1010_0101_u32, 0b0110_0101_u32));
    }
    #[test]
    fn superset_u32_3() {
        assert!(!superset_u32(0b1000_0101_u32, 0b0010_0101_u32));
    }
}
