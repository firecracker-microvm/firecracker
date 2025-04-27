// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring entropy devices.

use serde::{Deserialize, Serialize};

use crate::devices::virtio::TYPE_RNG;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::rng::{Entropy, EntropyError, RNG_NUM_QUEUES};
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyState {
    virtio_state: VirtioDeviceState,
    rate_limiter_state: RateLimiterState,
}

#[derive(Debug)]
pub struct EntropyConstructorArgs(GuestMemoryMmap);

impl EntropyConstructorArgs {
    pub fn new(mem: GuestMemoryMmap) -> Self {
        Self(mem)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EntropyPersistError {
    /// Create entropy: {0}
    CreateEntropy(#[from] EntropyError),
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
    /// Restore rate limiter: {0}
    RestoreRateLimiter(#[from] std::io::Error),
}

impl Persist<'_> for Entropy {
    type State = EntropyState;
    type ConstructorArgs = EntropyConstructorArgs;
    type Error = EntropyPersistError;

    fn save(&self) -> Self::State {
        EntropyState {
            virtio_state: VirtioDeviceState::from_device(self),
            rate_limiter_state: self.rate_limiter().save(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            &constructor_args.0,
            TYPE_RNG,
            RNG_NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;

        let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)?;
        let mut entropy = Entropy::new_with_queues(queues, rate_limiter)?;
        entropy.set_avail_features(state.virtio_state.avail_features);
        entropy.set_acked_features(state.virtio_state.acked_features);
        entropy.set_irq_status(state.virtio_state.interrupt_status);
        if state.virtio_state.activated {
            entropy.set_activated(constructor_args.0);
        }

        Ok(entropy)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::rng::device::ENTROPY_DEV_ID;
    use crate::devices::virtio::test_utils::test::create_virtio_mem;
    use crate::snapshot::Snapshot;

    #[test]
    fn test_persistence() {
        let mut mem = vec![0u8; 4096];
        let entropy = Entropy::new(RateLimiter::default()).unwrap();

        Snapshot::serialize(&mut mem.as_mut_slice(), &entropy.save()).unwrap();

        let guest_mem = create_virtio_mem();
        let restored = Entropy::restore(
            EntropyConstructorArgs(guest_mem),
            &Snapshot::deserialize(&mut mem.as_slice()).unwrap(),
        )
        .unwrap();

        assert_eq!(restored.device_type(), TYPE_RNG);
        assert_eq!(restored.id(), ENTROPY_DEV_ID);
        assert_eq!(restored.is_activated(), entropy.is_activated());
        assert_eq!(restored.avail_features(), entropy.avail_features());
        assert_eq!(restored.acked_features(), entropy.acked_features());
        assert_eq!(
            restored.interrupt_status().load(Ordering::Relaxed),
            entropy.interrupt_status().load(Ordering::Relaxed)
        );
    }
}
