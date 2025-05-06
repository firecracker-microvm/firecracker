// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring MmdsNetworkStack.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::ns::MmdsNetworkStack;
use crate::mmds::data_store::Mmds;
use crate::snapshot::Persist;
use crate::utils::net::mac::{MAC_ADDR_LEN, MacAddr};

/// State of a MmdsNetworkStack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdsNetworkStackState {
    mac_addr: [u8; MAC_ADDR_LEN as usize],
    ipv4_addr: u32,
    tcp_port: u16,
}

impl Persist<'_> for MmdsNetworkStack {
    type State = MmdsNetworkStackState;
    type ConstructorArgs = Arc<Mutex<Mmds>>;
    type Error = ();

    fn save(&self) -> Self::State {
        let mut mac_addr = [0; MAC_ADDR_LEN as usize];
        mac_addr.copy_from_slice(self.mac_addr.get_bytes());

        MmdsNetworkStackState {
            mac_addr,
            ipv4_addr: self.ipv4_addr.into(),
            tcp_port: self.tcp_handler.local_port(),
        }
    }

    fn restore(
        mmds: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(MmdsNetworkStack::new(
            MacAddr::from_bytes_unchecked(&state.mac_addr),
            Ipv4Addr::from(state.ipv4_addr),
            state.tcp_port,
            mmds,
        ))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::snapshot::Snapshot;

    #[test]
    fn test_persistence() {
        let ns = MmdsNetworkStack::new_with_defaults(None, Arc::new(Mutex::new(Mmds::default())));

        let mut mem = vec![0; 4096];

        Snapshot::serialize(&mut mem.as_mut_slice(), &ns.save()).unwrap();

        let restored_ns = MmdsNetworkStack::restore(
            Arc::new(Mutex::new(Mmds::default())),
            &Snapshot::deserialize(&mut mem.as_slice()).unwrap(),
        )
        .unwrap();

        assert_eq!(restored_ns.mac_addr, ns.mac_addr);
        assert_eq!(restored_ns.ipv4_addr, ns.ipv4_addr);
        assert_eq!(
            restored_ns.tcp_handler.local_port(),
            ns.tcp_handler.local_port()
        );
    }
}
