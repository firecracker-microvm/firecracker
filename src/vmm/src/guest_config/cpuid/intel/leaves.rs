// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::module_name_repetitions)]

#[allow(clippy::wildcard_imports)]
use crate::guest_config::cpuid::intel::registers::*;
use crate::guest_config::cpuid::Leaf;

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
