// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use crate::virtio::base::ring::{VirtqRingMirror, VirtqRingPtr};

/// Shadow structure for the following virtio struct:
/// ```C
/// struct virtq_used_elem {
///      le32 id;
///      le32 len;
/// };
/// ```
#[repr(C)]
pub struct VirtqUsedElem {
    pub(crate) id: u32,
    pub(crate) len: u32,
}

/// Mirror structure for the following virtio dynamically sized struct:
/// ```C
/// struct virtq_used {
///     le16 flags;
///     le16 idx;
///     struct virtq_used_elem ring[ /* Queue Size */ ];
///     le16 avail_event; /* Only if VIRTIO_F_EVENT_IDX */
/// };
/// ```
#[repr(C)]
pub struct VirtqUsedMirror {
    pub(crate) flags: u16,
    pub(crate) idx: u16,
    pub(crate) ring: [VirtqUsedElem; 0],
}

unsafe impl VirtqRingMirror for VirtqUsedMirror {
    type Element = VirtqUsedElem;
}

pub type VirtqUsedPtr = VirtqRingPtr<VirtqUsedMirror>;
