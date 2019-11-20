// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};

/// This struct represents the strongly typed equivalent of the json body
/// from vsock related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VsockDeviceConfig {
    /// ID of the vsock device.
    pub vsock_id: String,
    /// A 32-bit Context Identifier (CID) used to identify the guest.
    pub guest_cid: u32,
    /// Path to local unix socket.
    pub uds_path: String,
}

/// Errors associated with `VsockDeviceConfig`.
#[derive(Debug)]
pub enum VsockError {
    /// The update is not allowed after booting the microvm.
    UpdateNotAllowedPostBoot,
}

impl Display for VsockError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::VsockError::*;
        match *self {
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.",)
            }
        }
    }
}
