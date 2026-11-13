// Copyright (c) 2026 Tencent. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod qcow2;
pub mod vmdk;

use serde::{Deserialize, Serialize};

pub use self::qcow2::{Qcow2FileEngine, Qcow2IoError};
pub use self::vmdk::{VmdkFileEngine, VmdkIoError};

/// The disk image format of the backing file.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskImageFormat {
    /// Raw disk image (no format header).
    #[default]
    Raw,
    /// VMDK disk image.
    Vmdk,
    /// QCOW2 disk image.
    Qcow2,
}
