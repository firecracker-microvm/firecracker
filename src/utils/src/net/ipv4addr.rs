// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

/// Checks if an IPv4 address is RFC 3927 compliant.
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use utils::net::ipv4addr::is_link_local_valid;
///
/// is_link_local_valid(Ipv4Addr::new(169, 254, 1, 1));
///
pub fn is_link_local_valid(ipv4_addr: Ipv4Addr) -> bool {
    match ipv4_addr.octets() {
        [169, 254, 0, _] => false,
        [169, 254, 255, _] => false,
        [169, 254, _, _] => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::net::ipv4addr::is_link_local_valid;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_link_local_valid() {
        // Outside link-local IPv4 address range (169.254.0.0/16 - 169.254.255.255/16).
        let mut ipv4_addr = Ipv4Addr::new(1, 1, 1, 1);
        assert!(!is_link_local_valid(ipv4_addr));

        // First 256 addresses can not be used, per RFC 3927.
        ipv4_addr = Ipv4Addr::new(169, 254, 0, 0);
        assert!(!is_link_local_valid(ipv4_addr));
        ipv4_addr = Ipv4Addr::new(169, 254, 0, 10);
        assert!(!is_link_local_valid(ipv4_addr));
        ipv4_addr = Ipv4Addr::new(169, 254, 0, 255);
        assert!(!is_link_local_valid(ipv4_addr));

        // Last 256 addresses can not be used, per RFC 3927.
        ipv4_addr = Ipv4Addr::new(169, 254, 255, 0);
        assert!(!is_link_local_valid(ipv4_addr));
        ipv4_addr = Ipv4Addr::new(169, 254, 255, 194);
        assert!(!is_link_local_valid(ipv4_addr));
        ipv4_addr = Ipv4Addr::new(169, 254, 255, 255);
        assert!(!is_link_local_valid(ipv4_addr));

        // First valid IPv4 link-local address.
        ipv4_addr = Ipv4Addr::new(169, 254, 1, 0);
        assert!(is_link_local_valid(ipv4_addr));

        // Last valid IPv4 link-local address.
        ipv4_addr = Ipv4Addr::new(169, 254, 254, 255);
        assert!(is_link_local_valid(ipv4_addr));

        // In between valid IPv4 link-local address.
        ipv4_addr = Ipv4Addr::new(169, 254, 170, 2);
        assert!(is_link_local_valid(ipv4_addr));
    }
}
