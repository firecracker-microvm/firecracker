// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements Firecracker specific devices (e.g. signal when boot is completed).
mod boot_timer;
mod pvpanic;

pub use self::boot_timer::BootTimer;
pub use self::pvpanic::PvPanic;
