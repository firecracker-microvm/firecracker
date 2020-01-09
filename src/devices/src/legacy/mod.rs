// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod i8042;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
mod serial;

pub use self::i8042::Error as I8042DeviceError;
pub use self::i8042::I8042Device;
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::RTC;
pub use self::serial::{ReadableFd, Serial};
