// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring balloon devices.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::*;
use crate::devices::virtio::balloon::device::{BalloonStats, ConfigSpace, HintingState};
use crate::devices::virtio::device::{ActiveState, DeviceState};
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_BALLOON;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

/// Information about the balloon config's that are saved
/// at snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonConfigSpaceState {
    num_pages: u32,
    actual_pages: u32,
}

/// Information about the balloon stats that are saved
/// at snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    oom_kill: Option<u64>,
    alloc_stall: Option<u64>,
    async_scan: Option<u64>,
    direct_scan: Option<u64>,
    async_reclaim: Option<u64>,
    direct_reclaim: Option<u64>,
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
            oom_kill: stats.oom_kill,
            alloc_stall: stats.alloc_stall,
            async_scan: stats.async_scan,
            direct_scan: stats.direct_scan,
            async_reclaim: stats.async_reclaim,
            direct_reclaim: stats.direct_reclaim,
        }
    }

    fn create_stats(&self) -> BalloonStats {
        BalloonStats {
            target_pages: 0,
            actual_pages: 0,
            target_mib: 0,
            actual_mib: 0,
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
            oom_kill: self.oom_kill,
            alloc_stall: self.alloc_stall,
            async_scan: self.async_scan,
            direct_scan: self.direct_scan,
            async_reclaim: self.async_reclaim,
            direct_reclaim: self.direct_reclaim,
        }
    }
}

/// Information about the balloon that are saved
/// at snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonState {
    stats_polling_interval_s: u16,
    stats_desc_index: Option<u16>,
    latest_stats: BalloonStatsState,
    config_space: BalloonConfigSpaceState,
    hinting_state: HintingState,
    pub virtio_state: VirtioDeviceState,
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct BalloonConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
}

impl Persist<'_> for Balloon {
    type State = BalloonState;
    type ConstructorArgs = BalloonConstructorArgs;
    type Error = super::BalloonError;

    fn save(&self) -> Self::State {
        BalloonState {
            stats_polling_interval_s: self.stats_polling_interval_s,
            stats_desc_index: self.stats_desc_index,
            latest_stats: BalloonStatsState::from_stats(&self.latest_stats),
            hinting_state: self.hinting_state,
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
    ) -> Result<Self, Self::Error> {
        let free_page_hinting =
            state.virtio_state.avail_features & (1u64 << VIRTIO_BALLOON_F_FREE_PAGE_HINTING) != 0;

        let free_page_reporting =
            state.virtio_state.avail_features & (1u64 << VIRTIO_BALLOON_F_FREE_PAGE_REPORTING) != 0;

        // We can safely create the balloon with arbitrary flags and
        // num_pages because we will overwrite them after.
        let mut balloon = Balloon::new(
            0,
            false,
            state.stats_polling_interval_s,
            free_page_hinting,
            free_page_reporting,
        )?;

        let mut num_queues = BALLOON_MIN_NUM_QUEUES;
        // As per the virtio 1.1 specification, the statistics queue
        // should not exist if the statistics are not enabled.
        if state.stats_polling_interval_s > 0 {
            num_queues += 1;
        }

        if free_page_hinting {
            num_queues += 1;
        }

        if free_page_reporting {
            num_queues += 1;
        }

        balloon.queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VIRTIO_ID_BALLOON,
                num_queues,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(|_| Self::Error::QueueRestoreError)?;
        balloon.avail_features = state.virtio_state.avail_features;
        balloon.acked_features = state.virtio_state.acked_features;
        balloon.latest_stats = state.latest_stats.create_stats();
        balloon.config_space = ConfigSpace {
            num_pages: state.config_space.num_pages,
            actual_pages: state.config_space.actual_pages,
            // On restore allow the guest to reclaim pages
            free_page_hint_cmd_id: FREE_PAGE_HINT_DONE,
        };
        balloon.hinting_state = state.hinting_state;

        if state.virtio_state.activated && balloon.stats_enabled() {
            // Restore the stats descriptor.
            balloon.set_stats_desc_index(state.stats_desc_index);

            // Restart timer if needed.
            let duration = Duration::from_secs(state.stats_polling_interval_s as u64);
            balloon.stats_timer.arm(duration, Some(duration));
        }

        Ok(balloon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::{default_interrupt, default_mem};
    use crate::snapshot::Snapshot;

    #[test]
    fn test_persistence() {
        let guest_mem = default_mem();
        let mut mem = vec![0; 4096];

        // Create and save the balloon device.
        let balloon = Balloon::new(0x42, false, 2, false, false).unwrap();

        Snapshot::new(balloon.save())
            .save(&mut mem.as_mut_slice())
            .unwrap();

        // Deserialize and restore the balloon device.
        let restored_balloon = Balloon::restore(
            BalloonConstructorArgs { mem: guest_mem },
            &Snapshot::load_without_crc_check(mem.as_slice())
                .unwrap()
                .data,
        )
        .unwrap();

        assert_eq!(restored_balloon.device_type(), VIRTIO_ID_BALLOON);

        assert_eq!(restored_balloon.acked_features, balloon.acked_features);
        assert_eq!(restored_balloon.avail_features, balloon.avail_features);
        assert_eq!(
            restored_balloon.config_space.num_pages,
            balloon.config_space.num_pages
        );
        assert_eq!(
            restored_balloon.config_space.actual_pages,
            balloon.config_space.actual_pages
        );
        assert_eq!(
            restored_balloon.config_space.free_page_hint_cmd_id,
            FREE_PAGE_HINT_DONE
        );
        assert_eq!(restored_balloon.queues(), balloon.queues());
        assert!(!restored_balloon.is_activated());
        assert!(!balloon.is_activated());

        assert_eq!(
            restored_balloon.stats_polling_interval_s,
            balloon.stats_polling_interval_s
        );
        assert_eq!(restored_balloon.stats_desc_index, balloon.stats_desc_index);
        assert_eq!(restored_balloon.latest_stats, balloon.latest_stats);
    }
}
