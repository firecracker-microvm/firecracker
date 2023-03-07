// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Error type for `impl<T:std::fmt::Display> std::convert::TryFrom<std::collections::HashSet<T>>
/// for YourBitField`.
#[derive(Debug, thiserror::Error)]
#[error("Feature flag given in set which is not defined in bit field.")]
pub struct TryFromFlagSetError;

/// Error type for `impl<T:std::fmt::Display>
/// std::convert::TryFrom<std::collections::HashMap<T,YourBitField>> for YourBitField`.
#[derive(Debug, thiserror::Error)]
pub enum TryFromFieldMapError {
    /// Bit range given in map which is not defined in bit field.
    #[error("Bit range given in map which is not defined in bit field.")]
    UnknownRange,
    /// Failed to assign value from field map.
    #[error("Failed to assign value from field map: {0}")]
    CheckedAssign(#[from] CheckedAssignError),
}

/// Error type for `impl<T:std::fmt::Display>
/// std::convert::TryFrom<(std::collections::HashSet<T>,std::collections::HashMap<T,YourBitField>)>
/// for YourBitField`.
#[derive(Debug, thiserror::Error)]
pub enum TryFromFlagSetAndFieldMapError {
    /// Failed to parse flag set.
    #[error("Feature flag given in set which is not defined in bit field.")]
    MissingFlag,
    /// Bit range given in map which is not defined in bit field.
    #[error("Bit range given in map which is not defined in bit field.")]
    UnknownRange,
    /// Failed to assign value from field map.
    #[error("Failed to assign value from field map: {0}")]
    CheckedAssign(#[from] CheckedAssignError),
}

/// Error type for [`crate::BitRangeMut<u8, _, _>::checked_assign()`], [`crate::BitRangeMut<u16, _,
/// _>::checked_assign()`], etc.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Given value is greater than maximum storable value in bit range.")]
pub struct CheckedAssignError;
