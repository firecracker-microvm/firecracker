// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::module_name_repetitions)]
use std::fmt;

#[allow(clippy::wildcard_imports)]
use super::registers::*;
use crate::Leaf;

/// Cache and TLB information keywords.
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
    #[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", <Vec<&'static str>>::try_from(self).unwrap())
    }
}

/// Error type for [`<[&'static str; 16] as TryFrom<&Leaf2>>::try_from`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("Unknown cache and TLB information keyword: {0}")]
pub struct UnknownKeyword(u8);

/// Most significant bit
fn most_significant_bit(x: u8) -> bool {
    // SAFETY: 1 is less than the number of bits in `u8`.
    let mask = unsafe { u8::MAX.checked_shr(1).unwrap_unchecked() };
    (x & mask) == 1
}

impl TryFrom<&Leaf2> for Vec<&'static str> {
    type Error = UnknownKeyword;

    #[inline]
    fn try_from(leaf: &Leaf2) -> Result<Self, Self::Error> {
        let (a_opt, b_opt, c_opt, d_opt) = <(
            Option<[&'static str; 3]>,
            Option<[&'static str; 4]>,
            Option<[&'static str; 4]>,
            Option<[&'static str; 4]>,
        )>::try_from(leaf)?;
        let mut vec = Vec::new();
        if let Some(a) = a_opt {
            vec.extend(a);
        }
        if let Some(b) = b_opt {
            vec.extend(b);
        }
        if let Some(c) = c_opt {
            vec.extend(c);
        }
        if let Some(d) = d_opt {
            vec.extend(d);
        }
        Ok(vec)
    }
}

// - The least-significant-byte of eax always returns 01h, this value should be ignored.
// - The most significant bit is set to 0 when the register contains valid 1-byte descriptors.
impl TryFrom<&Leaf2>
    for (
        Option<[&'static str; 3]>,
        Option<[&'static str; 4]>,
        Option<[&'static str; 4]>,
        Option<[&'static str; 4]>,
    )
{
    type Error = UnknownKeyword;

    #[inline]
    fn try_from(leaf: &Leaf2) -> Result<Self, Self::Error> {
        Ok((
            if most_significant_bit(leaf.eax[3]) {
                None
            } else {
                Some([
                    KEYWORDS
                        .get(&leaf.eax[1])
                        .ok_or(UnknownKeyword(leaf.eax[1]))?,
                    KEYWORDS
                        .get(&leaf.eax[2])
                        .ok_or(UnknownKeyword(leaf.eax[2]))?,
                    KEYWORDS
                        .get(&leaf.eax[3])
                        .ok_or(UnknownKeyword(leaf.eax[3]))?,
                ])
            },
            if most_significant_bit(leaf.ebx[3]) {
                None
            } else {
                Some([
                    KEYWORDS
                        .get(&leaf.ebx[0])
                        .ok_or(UnknownKeyword(leaf.ebx[0]))?,
                    KEYWORDS
                        .get(&leaf.ebx[1])
                        .ok_or(UnknownKeyword(leaf.ebx[1]))?,
                    KEYWORDS
                        .get(&leaf.ebx[2])
                        .ok_or(UnknownKeyword(leaf.ebx[2]))?,
                    KEYWORDS
                        .get(&leaf.ebx[3])
                        .ok_or(UnknownKeyword(leaf.ebx[3]))?,
                ])
            },
            if most_significant_bit(leaf.ecx[3]) {
                None
            } else {
                Some([
                    KEYWORDS
                        .get(&leaf.ecx[0])
                        .ok_or(UnknownKeyword(leaf.ecx[0]))?,
                    KEYWORDS
                        .get(&leaf.ecx[1])
                        .ok_or(UnknownKeyword(leaf.ecx[1]))?,
                    KEYWORDS
                        .get(&leaf.ecx[2])
                        .ok_or(UnknownKeyword(leaf.ecx[2]))?,
                    KEYWORDS
                        .get(&leaf.ecx[3])
                        .ok_or(UnknownKeyword(leaf.ecx[3]))?,
                ])
            },
            if most_significant_bit(leaf.edx[3]) {
                None
            } else {
                Some([
                    KEYWORDS
                        .get(&leaf.edx[0])
                        .ok_or(UnknownKeyword(leaf.edx[0]))?,
                    KEYWORDS
                        .get(&leaf.edx[1])
                        .ok_or(UnknownKeyword(leaf.edx[1]))?,
                    KEYWORDS
                        .get(&leaf.edx[2])
                        .ok_or(UnknownKeyword(leaf.edx[2]))?,
                    KEYWORDS
                        .get(&leaf.edx[3])
                        .ok_or(UnknownKeyword(leaf.edx[3]))?,
                ])
            },
        ))
    }
}

impl From<(u32, u32, u32, u32)> for Leaf2 {
    #[inline]
    fn from((eax, ebx, ecx, edx): (u32, u32, u32, u32)) -> Self {
        Self {
            eax: eax.to_ne_bytes(),
            ebx: ebx.to_ne_bytes(),
            ecx: ecx.to_ne_bytes(),
            edx: edx.to_ne_bytes(),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Leaf types
// -------------------------------------------------------------------------------------------------

/// Leaf 02H
pub type Leaf2 = Leaf<[u8; 4], [u8; 4], [u8; 4], [u8; 4]>;

/// Leaf 03H
pub type Leaf3 = Leaf<Leaf3Eax, Leaf3Ebx, Leaf3Ecx, Leaf3Edx>;

/// Leaf 04H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf4<'a>(pub Vec<&'a Leaf4Subleaf>);

/// Leaf 04H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf4Mut<'a>(pub Vec<&'a mut Leaf4Subleaf>);

/// Leaf 04H subleaf
pub type Leaf4Subleaf = Leaf<Leaf4Eax, Leaf4Ebx, Leaf4Ecx, Leaf4Edx>;

/// Leaf 05H
pub type Leaf5 = Leaf<Leaf5Eax, Leaf5Ebx, Leaf5Ecx, Leaf5Edx>;

/// Leaf 06H
pub type Leaf6 = Leaf<Leaf6Eax, Leaf6Ebx, Leaf6Ecx, Leaf6Edx>;

/// Leaf 07H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf7<'a>(pub Option<&'a Leaf7Subleaf0>, pub Option<&'a Leaf7Subleaf1>);

/// Leaf 07H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf7Mut<'a>(
    pub Option<&'a mut Leaf7Subleaf0>,
    pub Option<&'a mut Leaf7Subleaf1>,
);

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

/// Leaf 0BH
#[derive(Debug, PartialEq, Eq)]
pub struct LeafB<'a>(pub Vec<&'a LeafBSubleaf>);

/// Leaf 0BH
#[derive(Debug, PartialEq, Eq)]
pub struct LeafBMut<'a>(pub Vec<&'a mut LeafBSubleaf>);

/// Leaf 0BH subleaf
pub type LeafBSubleaf = Leaf<LeafBEax, LeafBEbx, LeafBEcx, LeafBEdx>;

/// Leaf 0FH
#[derive(Debug, PartialEq, Eq)]
pub struct LeafF<'a>(pub Option<&'a LeafFSubleaf0>, pub Option<&'a LeafFSubleaf1>);

/// Leaf 0FH
#[derive(Debug, PartialEq, Eq)]
pub struct LeafFMut<'a>(
    pub Option<&'a mut LeafFSubleaf0>,
    pub Option<&'a mut LeafFSubleaf1>,
);

/// Leaf 0FH subleaf 0
pub type LeafFSubleaf0 =
    Leaf<LeafFSubleaf0Eax, LeafFSubleaf0Ebx, LeafFSubleaf0Ecx, LeafFSubleaf0Edx>;

/// Leaf 0FH subleaf 1
pub type LeafFSubleaf1 =
    Leaf<LeafFSubleaf1Eax, LeafFSubleaf1Ebx, LeafFSubleaf1Ecx, LeafFSubleaf1Edx>;

/// Leaf 10H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf10<'a>(
    pub Option<&'a Leaf10Subleaf0>,
    pub Option<&'a Leaf10Subleaf1>,
    pub Option<&'a Leaf10Subleaf2>,
    pub Option<&'a Leaf10Subleaf3>,
);

/// Leaf 10H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf10Mut<'a>(
    pub Option<&'a mut Leaf10Subleaf0>,
    pub Option<&'a mut Leaf10Subleaf1>,
    pub Option<&'a mut Leaf10Subleaf2>,
    pub Option<&'a mut Leaf10Subleaf3>,
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
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf12<'a>(
    pub Option<&'a Leaf12Subleaf0>,
    pub Option<&'a Leaf12Subleaf1>,
    pub Vec<&'a Leaf12SubleafGt1>,
);

/// Leaf 12H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf12Mut<'a>(
    pub Option<&'a mut Leaf12Subleaf0>,
    pub Option<&'a mut Leaf12Subleaf1>,
    pub Vec<&'a mut Leaf12SubleafGt1>,
);

/// Leaf 12H subleaf 0
pub type Leaf12Subleaf0 =
    Leaf<Leaf12Subleaf0Eax, Leaf12Subleaf0Ebx, Leaf12Subleaf0Ecx, Leaf12Subleaf0Edx>;

/// Leaf 12H subleaf 1
pub type Leaf12Subleaf1 =
    Leaf<Leaf12Subleaf1Eax, Leaf12Subleaf1Ebx, Leaf12Subleaf1Ecx, Leaf12Subleaf1Edx>;

/// Leaf 12H subleaf >1
pub type Leaf12SubleafGt1 =
    Leaf<Leaf12SubleafGt1Eax, Leaf12SubleafGt1Ebx, Leaf12SubleafGt1Ecx, Leaf12SubleafGt1Edx>;

/// Leaf 14H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf14<'a>(
    pub Option<&'a Leaf14Subleaf0>,
    pub Option<&'a Leaf14Subleaf1>,
);

/// Leaf 14H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf14Mut<'a>(
    pub Option<&'a mut Leaf14Subleaf0>,
    pub Option<&'a mut Leaf14Subleaf1>,
);
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
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf17<'a>(
    pub Option<&'a Leaf17Subleaf0>,
    pub Option<&'a Leaf17Subleaf1>,
    pub Option<&'a Leaf17Subleaf2>,
    pub Option<&'a Leaf17Subleaf3>,
);

/// Leaf 17H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf17Mut<'a>(
    pub Option<&'a mut Leaf17Subleaf0>,
    pub Option<&'a mut Leaf17Subleaf1>,
    pub Option<&'a mut Leaf17Subleaf2>,
    pub Option<&'a mut Leaf17Subleaf3>,
);

/// Leaf 18H subleaf 0
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
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf18<'a>(
    pub Option<&'a Leaf18Subleaf0>,
    pub Vec<&'a Leaf18SubleafGt0>,
);

/// Leaf 18H
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf18Mut<'a>(
    pub Option<&'a mut Leaf18Subleaf0>,
    pub Vec<&'a mut Leaf18SubleafGt0>,
);

/// Leaf 18H subleaf 0
pub type Leaf18Subleaf0 =
    Leaf<Leaf18Subleaf0Eax, Leaf18Subleaf0Ebx, Leaf18Subleaf0Ecx, Leaf18Subleaf0Edx>;

/// Leaf 18H subleaf 1
pub type Leaf18SubleafGt0 =
    Leaf<Leaf18SubleafGt0Eax, Leaf18SubleafGt0Ebx, Leaf18SubleafGt0Ecx, Leaf18SubleafGt0Edx>;

/// Leaf 19H
pub type Leaf19 = Leaf<Leaf19Eax, Leaf19Ebx, Leaf19Ecx, Leaf19Edx>;

/// Leaf 1AH
pub type Leaf1A = Leaf<Leaf1AEax, Leaf1AEbx, Leaf1AEcx, Leaf1AEdx>;

/// Leaf 1CH
pub type Leaf1C = Leaf<Leaf1CEax, Leaf1CEbx, Leaf1CEcx, Leaf1CEdx>;

/// Leaf 1FH
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf1F<'a>(pub Vec<&'a Leaf1FSubleaf>);

/// Leaf 1FH
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf1FMut<'a>(pub Vec<&'a mut Leaf1FSubleaf>);

/// Leaf 1F subleaf 1
pub type Leaf1FSubleaf = Leaf<Leaf1FEax, Leaf1FEbx, Leaf1FEcx, Leaf1FEdx>;

/// Leaf 20H
pub type Leaf20 = Leaf<Leaf20Eax, Leaf20Ebx, Leaf20Ecx, Leaf20Edx>;

/// Leaf 80000000H
pub type Leaf80000000 = Leaf<Leaf80000000Eax, Leaf80000000Ebx, Leaf80000000Ecx, Leaf80000000Edx>;

/// Leaf 80000001H
pub type Leaf80000001 = Leaf<Leaf80000001Eax, Leaf80000001Ebx, Leaf80000001Ecx, Leaf80000001Edx>;

/// Leaf 80000005H
pub type Leaf80000005 = Leaf<Leaf80000005Eax, Leaf80000005Ebx, Leaf80000005Ecx, Leaf80000005Edx>;

/// Leaf 80000006H
pub type Leaf80000006 = Leaf<Leaf80000006Eax, Leaf80000006Ebx, Leaf80000006Ecx, Leaf80000006Edx>;

/// Leaf 80000007H
pub type Leaf80000007 = Leaf<Leaf80000007Eax, Leaf80000007Ebx, Leaf80000007Ecx, Leaf80000007Edx>;

/// Leaf 80000008H
pub type Leaf80000008 = Leaf<Leaf80000008Eax, Leaf80000008Ebx, Leaf80000008Ecx, Leaf80000008Edx>;