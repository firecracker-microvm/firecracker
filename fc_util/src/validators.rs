// Misc data format validations, shared by multiple Firecracker components.
use std::fmt;

const MAX_INSTANCE_ID_LEN: usize = 64;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidChar(char, usize), // (char, position)
    InvalidLen(usize, usize), // (length, max)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidChar(ch, pos) => write!(f, "invalid char ({}) at position {}", ch, pos),
            Error::InvalidLen(len, max_len) => {
                write!(f, "invalid len ({}); max is {}", len, max_len)
            }
        }
    }
}

/// Validates an instance ID str.
/// An instance ID should not exceed MAX_INSTANCE_ID_LEN chars
/// and is only allowed to contain alphanumeric chars and hyphens.
pub fn validate_instance_id(input: &str) -> Result<(), Error> {
    if input.len() > MAX_INSTANCE_ID_LEN {
        return Err(Error::InvalidLen(input.len(), MAX_INSTANCE_ID_LEN));
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
        assert!(validate_instance_id("12-3aa").is_ok());
        assert_eq!(
            validate_instance_id("12:3aa").unwrap_err(),
            Error::InvalidChar(':', 2)
        );
        assert_eq!(
            validate_instance_id(str::repeat("a", MAX_INSTANCE_ID_LEN + 1).as_str()).unwrap_err(),
            Error::InvalidLen(MAX_INSTANCE_ID_LEN + 1, MAX_INSTANCE_ID_LEN)
        );
    }
}
