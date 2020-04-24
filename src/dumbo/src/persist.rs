// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring MmdsNetworkStack.

use std::net::Ipv4Addr;

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use super::ns::MmdsNetworkStack;
use super::*;

/// State of a MmdsNetworkStack.
#[derive(Versionize)]
pub struct MmdsNetworkStackState {
    mac_addr: [u8; MAC_ADDR_LEN],
    ipv4_addr: u32,
    tcp_port: u16,
    max_connections: usize,
    max_pending_resets: usize,
}

impl Persist for MmdsNetworkStack {
    type State = MmdsNetworkStackState;
    type ConstructorArgs = ();
    type Error = ();

    fn save(&self) -> Self::State {
        let mut mac_addr = [0; MAC_ADDR_LEN];
        mac_addr.copy_from_slice(self.mac_addr.get_bytes());

        MmdsNetworkStackState {
            mac_addr,
            ipv4_addr: self.ipv4_addr.into(),
            tcp_port: self.tcp_handler.local_port,
            max_connections: self.tcp_handler.max_connections,
            max_pending_resets: self.tcp_handler.max_pending_resets,
        }
    }

    fn restore(
        _: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(MmdsNetworkStack::new(
            MacAddr::from_bytes_unchecked(&state.mac_addr),
            Ipv4Addr::from(state.ipv4_addr),
            state.tcp_port,
            std::num::NonZeroUsize::new(state.max_connections).unwrap(),
            std::num::NonZeroUsize::new(state.max_pending_resets).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence() {
        let ns = MmdsNetworkStack::new_with_defaults(None);

        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        ns.save()
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_ns = MmdsNetworkStack::restore(
            (),
            &MmdsNetworkStackState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        assert_eq!(restored_ns.mac_addr, ns.mac_addr);
        assert_eq!(restored_ns.ipv4_addr, ns.ipv4_addr);
        assert_eq!(
            restored_ns.tcp_handler.local_port,
            ns.tcp_handler.local_port
        );
        assert_eq!(
            restored_ns.tcp_handler.max_connections,
            ns.tcp_handler.max_connections
        );
        assert_eq!(
            restored_ns.tcp_handler.max_pending_resets,
            ns.tcp_handler.max_pending_resets
        );
    }
}
