// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod ged;
mod vmgenid;

pub use ged::AcpiGenericEventDevice;
pub use vmgenid::Error as VMGenIDError;
pub use vmgenid::VMGenID;
