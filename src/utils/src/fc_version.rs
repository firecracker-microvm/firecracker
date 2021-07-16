use std::str::{FromStr, Split};

/// Errors related to FcVersion
#[derive(Debug)]
pub enum Error {
    /// Failed to create a FcVersion from a String
    InvalidFormat,
}

/// Represents a Firecracker version (e.g. 0.23.0)
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub struct FcVersion {
    major: u32,
    minor: u32,
    revision: u32,
}

impl FcVersion {
    /// Create a new instance of FcVersion
    pub const fn new(major: u32, minor: u32, revision: u32) -> FcVersion {
        FcVersion {
            major,
            minor,
            revision,
        }
    }
}

impl FromStr for FcVersion {
    type Err = Error;

    fn from_str(version_str: &str) -> Result<Self, Self::Err> {
        let mut parts = version_str.split('.');
        fn parse_next_part(parts: &mut Split<char>) -> Result<u32, Error> {
            parts
                .next()
                .ok_or(Error::InvalidFormat)?
                .parse()
                .map_err(|_| Error::InvalidFormat)
        }
        let major = parse_next_part(&mut parts)?;
        let minor = parse_next_part(&mut parts)?;
        let revision = parse_next_part(&mut parts)?;
        if parts.next() != None {
            return Err(Error::InvalidFormat);
        }

        Ok(FcVersion {
            major,
            minor,
            revision,
        })
    }
}

impl ToString for FcVersion {
    fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comparisons() {
        assert!(FcVersion::from_str("0.24.9").unwrap() < FcVersion::from_str("0.24.10").unwrap());
        assert!(FcVersion::from_str("0.23.0").unwrap() < FcVersion::from_str("0.24.0").unwrap());
        assert!(FcVersion::from_str("1.0.0").unwrap() > FcVersion::from_str("0.26.0").unwrap());
        assert_eq!(
            FcVersion::from_str("0.26.0").unwrap(),
            FcVersion::from_str("0.26.0").unwrap()
        );
    }

    #[test]
    fn test_from_str() {
        assert!(FcVersion::from_str("a.bb.c").is_err());
        assert!(FcVersion::from_str("0.24").is_err());
        assert!(FcVersion::from_str("0.24.0.1").is_err());
        assert!(FcVersion::from_str("0.24.x").is_err());
        assert!(FcVersion::from_str("0.24.0").is_ok());
    }

    #[test]
    fn test_to_string() {
        assert_eq!(FcVersion::new(0, 24, 0).to_string(), "0.24.0");
        assert_eq!(FcVersion::new(1, 15, 10).to_string(), "1.15.10");
        assert_eq!(
            FcVersion::new(1000, 2000000, 30000000).to_string(),
            "1000.2000000.30000000"
        );
    }
}
