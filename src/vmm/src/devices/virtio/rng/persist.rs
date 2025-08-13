// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring entropy devices.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::devices::virtio::TYPE_RNG;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::rng::{Entropy, EntropyError, RNG_NUM_QUEUES};
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyState {
    pub virtio_state: VirtioDeviceState,
    rate_limiter_state: RateLimiterState,
}

#[derive(Debug)]
pub struct EntropyConstructorArgs {
    pub mem: GuestMemoryMmap,
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
            &constructor_args.mem,
            TYPE_RNG,
            RNG_NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;

        let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)?;
        let mut entropy = Entropy::new_with_queues(queues, rate_limiter)?;
        entropy.set_avail_features(state.virtio_state.avail_features);
        entropy.set_acked_features(state.virtio_state.acked_features);

        Ok(entropy)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::rng::device::ENTROPY_DEV_ID;
    use crate::devices::virtio::test_utils::default_interrupt;
    use crate::devices::virtio::test_utils::test::create_virtio_mem;
    use crate::snapshot::Snapshot;

    #[test]
    fn test_persistence() {
        let mut mem = vec![0u8; 4096];
        let entropy = Entropy::new(RateLimiter::default()).unwrap();

        Snapshot::new(entropy.save())
            .save(&mut mem.as_mut_slice())
            .unwrap();

        let guest_mem = create_virtio_mem();
        let restored = Entropy::restore(
            EntropyConstructorArgs { mem: guest_mem },
            &Snapshot::load(&mut mem.as_slice()).unwrap().data,
        )
        .unwrap();

        assert_eq!(restored.device_type(), TYPE_RNG);
        assert_eq!(restored.id(), ENTROPY_DEV_ID);
        assert!(!restored.is_activated());
        assert!(!entropy.is_activated());
        assert_eq!(restored.avail_features(), entropy.avail_features());
        assert_eq!(restored.acked_features(), entropy.acked_features());
    }
}
