// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring balloon devices.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use timerfd::{SetTimeFlags, TimerState};

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use vm_memory::GuestMemoryMmap;

use super::*;

use crate::virtio::balloon::device::{BalloonStats, ConfigSpace};
use crate::virtio::persist::VirtioDeviceState;
use crate::virtio::{DeviceState, Queue};

#[derive(Clone, Versionize)]
pub struct BalloonConfigSpaceState {
    num_pages: u32,
    actual_pages: u32,
}

#[derive(Clone, Versionize)]
pub struct BalloonStatsState {
    swap_in: Option<u64>,
    swap_out: Option<u64>,
    major_faults: Option<u64>,
    minor_faults: Option<u64>,
    free_memory: Option<u64>,
    total_memory: Option<u64>,
    available_memory: Option<u64>,
    disk_caches: Option<u64>,
    hugetlb_allocations: Option<u64>,
    hugetlb_failures: Option<u64>,
}

impl BalloonStatsState {
    fn from_stats(stats: &BalloonStats) -> Self {
        Self {
            swap_in: stats.swap_in,
            swap_out: stats.swap_out,
            major_faults: stats.major_faults,
            minor_faults: stats.minor_faults,
            free_memory: stats.free_memory,
            total_memory: stats.total_memory,
            available_memory: stats.available_memory,
            disk_caches: stats.disk_caches,
            hugetlb_allocations: stats.hugetlb_allocations,
            hugetlb_failures: stats.hugetlb_failures,
        }
    }

    fn create_stats(&self) -> BalloonStats {
        BalloonStats {
            target_pages: 0,
            actual_pages: 0,
            target_mb: 0,
            actual_mb: 0,
            swap_in: self.swap_in,
            swap_out: self.swap_out,
            major_faults: self.major_faults,
            minor_faults: self.minor_faults,
            free_memory: self.free_memory,
            total_memory: self.total_memory,
            available_memory: self.available_memory,
            disk_caches: self.disk_caches,
            hugetlb_allocations: self.hugetlb_allocations,
            hugetlb_failures: self.hugetlb_failures,
        }
    }
}

#[derive(Clone, Versionize)]
pub struct BalloonState {
    stats_polling_interval_s: u16,
    stats_desc_index: Option<u16>,
    latest_stats: BalloonStatsState,
    config_space: BalloonConfigSpaceState,
    virtio_state: VirtioDeviceState,
}

pub struct BalloonConstructorArgs {
    pub mem: GuestMemoryMmap,
}

impl Persist<'_> for Balloon {
    type State = BalloonState;
    type ConstructorArgs = BalloonConstructorArgs;
    type Error = super::Error;

    fn save(&self) -> Self::State {
        BalloonState {
            stats_polling_interval_s: self.stats_polling_interval_s,
            stats_desc_index: self.stats_desc_index,
            latest_stats: BalloonStatsState::from_stats(&self.latest_stats),
            config_space: BalloonConfigSpaceState {
                num_pages: self.config_space.num_pages,
                actual_pages: self.config_space.actual_pages,
            },
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        // We can safely create the balloon with arbitrary flags and
        // num_pages because we will overwrite them after.
        let mut balloon = Balloon::new(0, false, false, state.stats_polling_interval_s, true)?;

        balloon.queues = state
            .virtio_state
            .queues
            .iter()
            .map(|queue_state| Queue::restore((), &queue_state).unwrap())
            .collect();
        balloon.interrupt_status = Arc::new(AtomicUsize::new(state.virtio_state.interrupt_status));
        balloon.avail_features = state.virtio_state.avail_features;
        balloon.acked_features = state.virtio_state.acked_features;
        balloon.latest_stats = state.latest_stats.create_stats();
        balloon.config_space = ConfigSpace {
            num_pages: state.config_space.num_pages,
            actual_pages: state.config_space.actual_pages,
        };

        if state.virtio_state.activated {
            balloon.device_state = DeviceState::Activated(constructor_args.mem);

            // Restart timer if needed.
            if balloon.stats_enabled() {
                let timer_state = TimerState::Periodic {
                    current: Duration::from_secs(state.stats_polling_interval_s as u64),
                    interval: Duration::from_secs(state.stats_polling_interval_s as u64),
                };
                balloon
                    .stats_timer
                    .set_state(timer_state, SetTimeFlags::Default);
            }
        }

        Ok(balloon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::device::VirtioDevice;
    use crate::virtio::TYPE_BALLOON;

    use crate::virtio::test_utils::default_mem;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_persistence() {
        let guest_mem = default_mem();
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        // Create and save the balloon device.
        let mut balloon = Balloon::new(0x42, true, false, 2, false).unwrap();
        balloon.activate(guest_mem.clone()).unwrap();

        <Balloon as Persist>::save(&balloon)
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        // Deserialize and restore the balloon device.
        let restored_balloon = Balloon::restore(
            BalloonConstructorArgs { mem: guest_mem },
            &BalloonState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        assert_eq!(restored_balloon.device_type(), TYPE_BALLOON);
        assert!(restored_balloon.restored);

        assert_eq!(restored_balloon.acked_features, balloon.acked_features);
        assert_eq!(restored_balloon.avail_features, balloon.avail_features);
        assert_eq!(restored_balloon.config_space, balloon.config_space);
        assert_eq!(restored_balloon.queues(), balloon.queues());
        assert_eq!(
            restored_balloon.interrupt_status().load(Ordering::Relaxed),
            balloon.interrupt_status().load(Ordering::Relaxed)
        );
        assert_eq!(restored_balloon.is_activated(), balloon.is_activated());

        assert_eq!(
            restored_balloon.stats_polling_interval_s,
            balloon.stats_polling_interval_s
        );
        assert_eq!(restored_balloon.stats_desc_index, balloon.stats_desc_index);
        assert_eq!(restored_balloon.latest_stats, balloon.latest_stats);
    }
}
