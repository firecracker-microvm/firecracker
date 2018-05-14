use std::result::Result;

use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};

pub const MAC_ADDR_LEN: usize = 6;

#[derive(Clone, Debug, PartialEq)]
pub struct MacAddr {
    bytes: [u8; MAC_ADDR_LEN],
}

impl MacAddr {
    // The error contains the str that failed to be parsed, for nicer error message generation.
    pub fn parse_str<'a, S>(s: &'a S) -> Result<MacAddr, &'a str>
    where
        S: AsRef<str> + ?Sized,
    {
        let v: Vec<&str> = s.as_ref().split(':').collect();
        let mut bytes = [0u8; MAC_ADDR_LEN];

        if v.len() != MAC_ADDR_LEN {
            return Err(s.as_ref());
        }

        for i in 0..MAC_ADDR_LEN {
            if v[i].len() != 2 {
                return Err(s.as_ref());
            }
            bytes[i] = u8::from_str_radix(v[i], 16).map_err(|_| s.as_ref())?;
        }

        Ok(MacAddr { bytes })
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_string(&self) -> String {
        let b = &self.bytes;
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<MacAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        MacAddr::parse_str(&s).map_err(|_| D::Error::custom("The provided MAC address is invalid."))
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_mac_addr() {
        // too long
        assert!(MacAddr::parse_str("aa:aa:aa:aa:aa:aa:aa").is_err());

        // invalid hex
        assert!(MacAddr::parse_str("aa:aa:aa:aa:aa:ax").is_err());

        // single digit mac address component should be invalid
        assert!(MacAddr::parse_str("aa:aa:aa:aa:aa:b").is_err());

        // components with more than two digits should also be invalid
        assert!(MacAddr::parse_str("aa:aa:aa:aa:aa:bbb").is_err());

        let mac = MacAddr::parse_str("12:34:56:78:9a:BC").unwrap();

        println!("parsed MAC address: {}", mac.to_string());

        let bytes = mac.get_bytes();
        assert_eq!(bytes, [0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
    }

    #[test]
    fn test_mac_addr_serialization_and_deserialization() {
        let mac: MacAddr =
            serde_json::from_str("\"12:34:56:78:9a:bc\"").expect("MacAddr deserialization failed.");

        let bytes = mac.get_bytes();
        assert_eq!(bytes, [0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc]);

        let s = serde_json::to_string(&mac).expect("MacAddr serialization failed.");
        assert_eq!(s, "\"12:34:56:78:9a:bc\"");
    }
}
