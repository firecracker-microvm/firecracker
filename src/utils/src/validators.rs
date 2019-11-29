// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Misc data format validations, shared by multiple Firecracker components.
use std::fmt;

const MAX_INSTANCE_ID_LEN: usize = 64;
const MIN_INSTANCE_ID_LEN: usize = 1;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidChar(char, usize),        // (char, position)
    InvalidLen(usize, usize, usize), // (length, min, max)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidChar(ch, pos) => write!(f, "invalid char ({}) at position {}", ch, pos),
            Error::InvalidLen(len, min_len, max_len) => write!(
                f,
                "invalid len ({});  the length must be between {} and {}",
                len, min_len, max_len
            ),
        }
    }
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
            "invalid len (0);  the length must be between 1 and 64"
        );
        assert!(validate_instance_id("12-3aa").is_ok());
        assert_eq!(
            format!("{}", validate_instance_id("12_3aa").unwrap_err()),
            "invalid char (_) at position 2"
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
