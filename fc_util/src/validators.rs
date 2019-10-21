// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Misc data format validations, shared by multiple Firecracker components.
extern crate regex;

use std::fmt;

const REGEX_INSTANCE_ID: &str = r"^[a-zA-Z0-9]([a-zA-Z0-9-]){0,63}$";

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInput(),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidInput() => write!(f, "invalid input"),
        }
    }
}

/// Checks that the instance id only contains alphanumeric chars and hyphens
/// and that the size is between 1 and 64 characters.
pub fn validate_instance_id(input: &str) -> Result<(), Error> {
    let re = regex::Regex::new(REGEX_INSTANCE_ID).unwrap();

    if !re.is_match(input) {
        return Err(Error::InvalidInput());
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
            "invalid input"
        );

        let long_str = str::repeat("a", 64);
        let overflow = str::repeat("a", 65);

        let inputs = [
            ("12-3aa", true),
            ("12-3aa-bb", true),
            (long_str.as_str(), true),
            ("a", true),
            ("", false),
            ("12_3aa", false),
            ("12:3aa", false),
            (overflow.as_str(), false),
        ];

        for input in &inputs {
            assert_eq!(validate_instance_id((*input).0).is_ok(), (*input).1);
        }
    }
}
