// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use crate::virtio::base::ring::{VirtqRingMirror, VirtqRingPtr};

/// Shadow structure for the following virtio struct:
/// ```C
/// struct virtq_desc {
///     le64 addr;
///     le32 len;
///     le16 flags;
///     le16 next;
/// };
/// ```
#[repr(C)]
pub struct VirtqDesc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

/// Mirror structure for the following virtio dynamically sized struct:
/// ```C
/// struct virtq_desc desc[ Queue Size ];
/// ```
#[repr(C)]
pub struct VirtqDescMirror {
    pub ring: [VirtqDesc; 0],
}

unsafe impl VirtqRingMirror for VirtqDescMirror {
    type Element = VirtqDesc;
}

pub type VirtqDescPtr = VirtqRingPtr<VirtqDescMirror>;
