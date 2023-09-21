// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Misc data format validations, shared by multiple Firecracker components.

const MAX_INSTANCE_ID_LEN: usize = 64;
const MIN_INSTANCE_ID_LEN: usize = 1;

#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Invalid char ({0}) at position {1}
    InvalidChar(char, usize), // (char, position)
    /// Invalid len ({0});  the length must be between {1} and {2}
    InvalidLen(usize, usize, usize), // (length, min, max)
}

/// Checks that the instance id only contains alphanumeric chars and hyphens
/// and that the size is between 1 and 64 characters.
pub fn validate_instance_id(input: &str) -> Result<(), Error> {
    if input.len() > MAX_INSTANCE_ID_LEN || input.len() < MIN_INSTANCE_ID_LEN {
        return Err(Error::InvalidLen(
            input.len(),
            MIN_INSTANCE_ID_LEN,
            MAX_INSTANCE_ID_LEN,
        ));
    }
    for (i, c) in input.chars().enumerate() {
        if !(c == '-' || c.is_alphanumeric()) {
            return Err(Error::InvalidChar(c, i));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_instance_id() {
        assert_eq!(
            format!("{}", validate_instance_id("").unwrap_err()),
            "Invalid len (0);  the length must be between 1 and 64"
        );
        assert!(validate_instance_id("12-3aa").is_ok());
        assert_eq!(
            format!("{}", validate_instance_id("12_3aa").unwrap_err()),
            "Invalid char (_) at position 2"
        );
        assert_eq!(
            validate_instance_id("12:3aa").unwrap_err(),
            Error::InvalidChar(':', 2)
        );
        assert_eq!(
            validate_instance_id(str::repeat("a", MAX_INSTANCE_ID_LEN + 1).as_str()).unwrap_err(),
            Error::InvalidLen(
                MAX_INSTANCE_ID_LEN + 1,
                MIN_INSTANCE_ID_LEN,
                MAX_INSTANCE_ID_LEN
            )
        );
    }
}
