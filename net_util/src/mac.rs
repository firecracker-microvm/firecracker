use std::result::Result;

pub const MAC_ADDR_LEN: usize = 6;

#[derive(Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr() {
        // too long
        assert!(MacAddr::parse_str("aa:aa:aa:aa:aa:aa:aa").is_err());
        // invalid hex
        assert!(MacAddr::parse_str("aa:aa:aa:aa:aa:ax").is_err());

        let mac = MacAddr::parse_str("12:34:56:78:9a:BC").unwrap();

        println!("parsed MAC address: {}", mac.to_string());

        let bytes = mac.get_bytes();
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);
        assert_eq!(bytes[2], 0x56);
        assert_eq!(bytes[3], 0x78);
        assert_eq!(bytes[4], 0x9a);
        assert_eq!(bytes[5], 0xbc);
    }
}
