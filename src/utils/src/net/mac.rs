// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Contains support for parsing and constructing MAC addresses
//! More information about MAC addresses can be found [here]
//!
//! [here]: https://en.wikipedia.org/wiki/MAC_address

use std::fmt;
use std::result::Result;
use std::str::FromStr;

use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};

/// The number of tuples (the ones separated by ":") contained in a MAC address.
pub const MAC_ADDR_LEN: u8 = 6;

/// Represents a MAC address
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
/// Representation of a MAC address.
pub struct MacAddr {
    bytes: [u8; MAC_ADDR_LEN as usize],
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = &self.bytes;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.bytes
    }
}

impl FromStr for MacAddr {
    type Err = String;
    /// Try to turn a `&str` into a `MacAddr` object. The method will return the `str` that failed
    /// to be parsed.
    /// # Arguments
    ///
    /// * `s` - reference that can be converted to &str.
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use self::utils::net::mac::MacAddr;
    /// MacAddr::from_str("12:34:56:78:9a:BC").unwrap();
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: Vec<&str> = s.split(':').collect();
        let mut bytes = [0u8; MAC_ADDR_LEN as usize];

        if v.len() != MAC_ADDR_LEN as usize {
            return Err(String::from(s));
        }

        for i in 0..MAC_ADDR_LEN as usize {
            if v[i].len() != 2 {
                return Err(String::from(s));
            }
            bytes[i] = u8::from_str_radix(v[i], 16).map_err(|_| String::from(s))?;
        }

        Ok(MacAddr { bytes })
    }
}

impl MacAddr {
    /// Create a `MacAddr` from a slice.
    /// Does not check whether `src.len()` == `MAC_ADDR_LEN`.
    /// # Arguments
    ///
    /// * `src` - slice from which to copy MAC address content.
    /// # Example
    ///
    /// ```
    /// use self::utils::net::mac::MacAddr;
    /// let mac = MacAddr::from_bytes_unchecked(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    /// println!("{}", mac.to_string());
    /// ```
    #[inline]
    pub fn from_bytes_unchecked(src: &[u8]) -> MacAddr {
        // TODO: using something like std::mem::uninitialized could avoid the extra initialization,
        // if this ever becomes a performance bottleneck.
        let mut bytes = [0u8; MAC_ADDR_LEN as usize];
        bytes[..].copy_from_slice(src);

        MacAddr { bytes }
    }

    /// Return the underlying content of this `MacAddr` in bytes.
    /// # Example
    ///
    /// ```
    /// use self::utils::net::mac::MacAddr;
    /// let mac = MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    /// assert_eq!([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], mac.get_bytes());
    /// ```
    #[inline]
    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<MacAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;
        MacAddr::from_str(&s).map_err(|_| D::Error::custom("The provided MAC address is invalid."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr() {
        // too long
        MacAddr::from_str("aa:aa:aa:aa:aa:aa:aa").unwrap_err();

        // invalid hex
        MacAddr::from_str("aa:aa:aa:aa:aa:ax").unwrap_err();

        // single digit mac address component should be invalid
        MacAddr::from_str("aa:aa:aa:aa:aa:b").unwrap_err();

        // components with more than two digits should also be invalid
        MacAddr::from_str("aa:aa:aa:aa:aa:bbb").unwrap_err();

        let mac = MacAddr::from_str("12:34:56:78:9a:BC").unwrap();

        println!("parsed MAC address: {}", mac);

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
