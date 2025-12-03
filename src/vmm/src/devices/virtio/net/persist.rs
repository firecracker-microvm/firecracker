// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring net devices.

use std::io;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::device::{Net, RxBuffers};
use super::{NET_NUM_QUEUES, NET_QUEUE_MAX_SIZE, RX_INDEX, TapError};
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::mmds::data_store::Mmds;
use crate::mmds::ns::MmdsNetworkStack;
use crate::mmds::persist::MmdsNetworkStackState;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::utils::net::mac::MacAddr;
use crate::vstate::memory::GuestMemoryMmap;

/// Information about the network config's that are saved
/// at snapshot.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetConfigSpaceState {
    guest_mac: Option<MacAddr>,
}

/// Information about the network device that are saved
/// at snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetState {
    pub id: String,
    pub tap_if_name: String,
    rx_rate_limiter_state: RateLimiterState,
    tx_rate_limiter_state: RateLimiterState,
    /// The associated MMDS network stack.
    pub mmds_ns: Option<MmdsNetworkStackState>,
    config_space: NetConfigSpaceState,
    pub virtio_state: VirtioDeviceState,
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct NetConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// Pointer to the MMDS data store.
    pub mmds: Option<Arc<Mutex<Mmds>>>,
}

/// Errors triggered when trying to construct a network device at resume time.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NetPersistError {
    /// Failed to create a network device: {0}
    CreateNet(#[from] super::NetError),
    /// Failed to create a rate limiter: {0}
    CreateRateLimiter(#[from] io::Error),
    /// Failed to re-create the virtio state (i.e queues etc): {0}
    VirtioState(#[from] VirtioStateError),
    /// Indicator that no MMDS is associated with this device.
    NoMmdsDataStore,
    /// Setting tap interface offload flags failed: {0}
    TapSetOffload(TapError),
}

impl Persist<'_> for Net {
    type State = NetState;
    type ConstructorArgs = NetConstructorArgs;
    type Error = NetPersistError;

    fn save(&self) -> Self::State {
        NetState {
            id: self.id.clone(),
            tap_if_name: self.iface_name(),
            rx_rate_limiter_state: self.rx_rate_limiter.save(),
            tx_rate_limiter_state: self.tx_rate_limiter.save(),
            mmds_ns: self.mmds_ns.as_ref().map(|mmds| mmds.save()),
            config_space: NetConfigSpaceState {
                guest_mac: self.guest_mac,
            },
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // RateLimiter::restore() can fail at creating a timerfd.
        let rx_rate_limiter = RateLimiter::restore((), &state.rx_rate_limiter_state)?;
        let tx_rate_limiter = RateLimiter::restore((), &state.tx_rate_limiter_state)?;
        let mut net = Net::new(
            state.id.clone(),
            &state.tap_if_name,
            state.config_space.guest_mac,
            rx_rate_limiter,
            tx_rate_limiter,
        )?;

        // We trust the MMIODeviceManager::restore to pass us an MMDS data store reference if
        // there is at least one net device having the MMDS NS present and/or the mmds version was
        // persisted in the snapshot.
        if let Some(mmds_ns) = &state.mmds_ns {
            // We're safe calling unwrap() to discard the error, as MmdsNetworkStack::restore()
            // always returns Ok.
            net.mmds_ns = Some(
                MmdsNetworkStack::restore(
                    constructor_args
                        .mmds
                        .map_or_else(|| Err(NetPersistError::NoMmdsDataStore), Ok)?,
                    mmds_ns,
                )
                .unwrap(),
            );
        }

        net.queues = state.virtio_state.build_queues_checked(
            &constructor_args.mem,
            VirtioDeviceType::Net,
            NET_NUM_QUEUES,
            NET_QUEUE_MAX_SIZE,
        )?;
        net.avail_features = state.virtio_state.avail_features;
        net.acked_features = state.virtio_state.acked_features;

        Ok(net)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::net::test_utils::{default_net, default_net_no_mmds};
    use crate::devices::virtio::test_utils::{default_interrupt, default_mem};
    use crate::snapshot::Snapshot;

    fn validate_save_and_restore(net: Net, mmds_ds: Option<Arc<Mutex<Mmds>>>) {
        let guest_mem = default_mem();
        let mut mem = vec![0; 4096];

        let id;
        let tap_if_name;
        let has_mmds_ns;
        let allow_mmds_requests;
        let virtio_state;

        // Create and save the net device.
        {
            Snapshot::new(net.save())
                .save(&mut mem.as_mut_slice())
                .unwrap();

            // Save some fields that we want to check later.
            id = net.id.clone();
            tap_if_name = net.iface_name();
            has_mmds_ns = net.mmds_ns.is_some();
            allow_mmds_requests = has_mmds_ns && mmds_ds.is_some();
            virtio_state = VirtioDeviceState::from_device(&net);
        }

        // Drop the initial net device so that we don't get an error when trying to recreate the
        // TAP device.
        drop(net);
        {
            // Deserialize and restore the net device.
            match Net::restore(
                NetConstructorArgs {
                    mem: guest_mem,
                    mmds: mmds_ds,
                },
                &Snapshot::load_without_crc_check(mem.as_slice())
                    .unwrap()
                    .data,
            ) {
                Ok(restored_net) => {
                    // Test that virtio specific fields are the same.
                    assert_eq!(restored_net.device_type(), VirtioDeviceType::Net);
                    assert_eq!(restored_net.avail_features(), virtio_state.avail_features);
                    assert_eq!(restored_net.acked_features(), virtio_state.acked_features);
                    assert_eq!(restored_net.is_activated(), virtio_state.activated);

                    // Test that net specific fields are the same.
                    assert_eq!(&restored_net.id, &id);
                    assert_eq!(&restored_net.iface_name(), &tap_if_name);
                    assert_eq!(restored_net.mmds_ns.is_some(), allow_mmds_requests);
                    assert_eq!(restored_net.rx_rate_limiter, RateLimiter::default());
                    assert_eq!(restored_net.tx_rate_limiter, RateLimiter::default());
                }
                Err(NetPersistError::NoMmdsDataStore) => {
                    assert!(has_mmds_ns && !allow_mmds_requests)
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_persistence() {
        let mmds = Some(Arc::new(Mutex::new(Mmds::default())));
        validate_save_and_restore(default_net(), mmds.as_ref().cloned());
        validate_save_and_restore(default_net_no_mmds(), None);

        // Check what happens if the MMIODeviceManager gives us the reference to the MMDS
        // data store even if this device does not have mmds ns configured.
        // The restore should be conservative and not configure the mmds ns.
        validate_save_and_restore(default_net_no_mmds(), mmds);

        // Check what happens if the MMIODeviceManager does not give us the reference to the MMDS
        // data store. This will return an error.
        validate_save_and_restore(default_net(), None);
    }
}
