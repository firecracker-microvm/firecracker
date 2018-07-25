//! Validate UUIDs.
//! A UUID is an unique number of 128bit.  UUIDs are used to  assign
//! unique identifiers to entities.
//! Check against 3 formats specified by the RFC: https://tools.ietf.org/html/rfc4122.
//! * simple:       9856BAC1F9CBD6b9d80C712AF75C832A7
//! * hyphenated:   551e7604-e35c-42b3-b825-416853441234
//! * urn: urn:uuid:551e7604-e35c-42b3-b825-416853441234
use std::result;

#[derive(Debug, PartialEq)]
pub enum UUIDError {
    InvalidChar(char),
    InvalidGroupCount(usize),
    InvalidLength(usize),
    InvalidGroupLength(u8),
}

type Result<T> = result::Result<T, UUIDError>;

// Length of each of the 5 hyphen delimited groups from the RFC.
const GROUP_LENS: [u8; 5] = [8, 4, 4, 4, 12];
const HYPHEN_FORMAT_GROUP_COUNT: usize = 4;
const HYPHEN_FORMAT_LEN: usize = 36;
const SIMPLE_FORMAT_LEN: usize = 32;
const URN_FORMAT_PREFIX_LEN: usize = 9;

/// Validate a `Uuid` from a string of hexadecimal digits against three of the
/// supported formats.
pub fn validate(mut input: &str) -> Result<()> {
    // Check against correct length of each format.
    let len = input.len();
    if input.starts_with("urn:uuid:") && len == (HYPHEN_FORMAT_LEN + URN_FORMAT_PREFIX_LEN) {
        input = &input[9..];
    } else if len != SIMPLE_FORMAT_LEN && len != HYPHEN_FORMAT_LEN {
        return Err(UUIDError::InvalidLength(len));
    }

    // Used to count digits from each group.
    let mut group_index = 0;
    let mut group_count = 0;

    // Iterate over index and value of each byte of the input string.
    for (index, value) in input.bytes().enumerate() {
        // If length is bigger than that of the simple format, check that the
        // groups are exactly 4 at this moment.
        if index as usize >= SIMPLE_FORMAT_LEN && group_index != HYPHEN_FORMAT_GROUP_COUNT {
            return Err(UUIDError::InvalidGroupCount(group_index + 1));
        }
        // Never let the UUID get more than 5 groups.
        if group_index > HYPHEN_FORMAT_GROUP_COUNT {
            return Err(UUIDError::InvalidGroupCount(group_index + 1));
        }
        match value {
            b'0'...b'9' => group_count += 1,
            b'a'...b'f' => group_count += 1,
            b'A'...b'F' => group_count += 1,
            // With each hyphen we need to make sure that the
            // number of digits from the current group meets the RFC.
            b'-' => {
                if GROUP_LENS[group_index] != group_count {
                    return Err(UUIDError::InvalidGroupLength(group_count));
                }
                group_index += 1;
                group_count = 0;
            }
            _ => {
                return Err(UUIDError::InvalidChar(
                    input[index..].chars().next().unwrap(),
                ))
            }
        }
    }
    if group_index > 0 && GROUP_LENS[group_index] != group_count {
        return Err(UUIDError::InvalidGroupLength(group_count));
    }
    Ok(())
}

mod tests {
    #[test]
    fn test_uuid_validate() {
        use super::*;

        // Testing invalid uuids.
        assert_eq!(validate(""), Err(UUIDError::InvalidLength(0)));
        assert_eq!(validate("a"), Err(UUIDError::InvalidLength(1)));
        assert_eq!(
            validate("551e7604-CDB3-5fbb-C6ADD-338BD51DB2F5"),
            Err(UUIDError::InvalidLength(37))
        );
        assert_eq!(
            validate("551e7604-DFC3A5abbAC7CAA431CA48AB2F3"),
            Err(UUIDError::InvalidGroupCount(2))
        );
        assert_eq!(
            validate("551e7604-DFC3-DFC3A5abbAC7CAA431CA48"),
            Err(UUIDError::InvalidGroupCount(3))
        );
        assert_eq!(
            validate("551e7604-DFC3-DFC3X5AbbAC7CAA431CA48"),
            Err(UUIDError::InvalidChar('X'))
        );

        assert_eq!(
            validate("551e7604-DAF-35ab-fC7CAA43-CA48AB2F5"),
            Err(UUIDError::InvalidGroupLength(3))
        );
        assert_eq!(
            validate("01020304-1112-2122-3132-41424344"),
            Err(UUIDError::InvalidGroupLength(8))
        );
        assert_eq!(
            validate("67e5604510c1436%9257bca00e6fe1da"),
            Err(UUIDError::InvalidChar('%'))
        );
        assert_eq!(
            validate("342342323323534535435434587353276861"),
            Err(UUIDError::InvalidGroupCount(1))
        );

        // Testing valid ones also.
        assert!(validate("00000000000000000000000000000000").is_ok());
        assert!(validate("68f56045-20c2-437a-8257-bb781e5ae0c9").is_ok());
        assert!(validate("F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4").is_ok());
        assert!(validate("67e5504410b1426f9247bb680e5fe0c8").is_ok());
        assert!(validate("01020304-1112-2122-3132-414243444546").is_ok());
        assert!(validate("urn:uuid:67e55044-10b1-426f-9247-bb680e5fe0c8").is_ok());

        assert!(validate("00000000000000000000000000000000").is_ok());
        assert!(validate("00000000-0000-0000-0000-000000000000").is_ok());
    }
}
