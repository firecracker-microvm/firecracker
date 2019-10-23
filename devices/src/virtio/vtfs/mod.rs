// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod device;
mod error;
mod filesystem;
mod util;

pub use self::device::Vtfs;

pub const TYPE_FS: u32 = 26;

// Number of DeviceEventT events supported by this implementation.
pub const VTFS_EVENTS_COUNT: usize = 2;
