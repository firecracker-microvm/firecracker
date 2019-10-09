// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use crate::virtio::base::ring::{VirtqRingMirror, VirtqRingPtr};

/// Mirror structure for the following virtio dynamically sized struct:
/// ```C
/// struct virtq_avail {
///     le16 flags;
///     le16 idx;
///     le16 ring[ /* Queue Size */ ];
///     le16 used_event; /* Only if VIRTIO_F_EVENT_IDX */
/// };
/// ```
#[repr(C)]
pub struct VirtqAvailMirror {
    pub(crate) flags: u16,
    pub(crate) idx: u16,
    pub(crate) ring: [u16; 0],
}

unsafe impl VirtqRingMirror for VirtqAvailMirror {
    type Element = u16;
}

pub type VirtqAvailPtr = VirtqRingPtr<VirtqAvailMirror>;
