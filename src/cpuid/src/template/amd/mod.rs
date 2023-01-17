// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Follows the T2 template for setting up the CPUID.
/// Also disables AMD-specific features.
pub mod t2a;

use crate::common::{get_vendor_id_from_host, VENDOR_ID_AMD};
use crate::transformer::Error;

pub fn validate_vendor_id() -> Result<(), Error> {
    let vendor_id = get_vendor_id_from_host()?;
    if &vendor_id != VENDOR_ID_AMD {
        return Err(Error::InvalidVendor);
    }

    Ok(())
}
