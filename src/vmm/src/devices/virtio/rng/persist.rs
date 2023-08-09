// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring entropy devices.

use snapshot::Persist;
use utils::vm_memory::GuestMemoryMmap;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use crate::devices::virtio::persist::PersistError as VirtioStateError;
use crate::devices::virtio::rng::{Entropy, EntropyError, RNG_NUM_QUEUES};
use crate::devices::virtio::{VirtioDeviceState, FIRECRACKER_MAX_QUEUE_SIZE, TYPE_RNG};
use crate::rate_limiter::persist::RateLimiterState;
use crate::rate_limiter::RateLimiter;

#[derive(Debug, Clone, Versionize)]
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

#[derive(Debug, derive_more::From)]
pub enum EntropyPersistError {
    CreateEntropy(EntropyError),
    VirtioState(VirtioStateError),
    RestoreRateLimiter(std::io::Error),
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

    #[test]
    fn test_persistence() {
        let mut mem = vec![0u8; 4096];
        let entropy = Entropy::new(RateLimiter::default()).unwrap();

        let version_map = VersionMap::new();
        <Entropy as Persist>::save(&entropy)
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let guest_mem = create_virtio_mem();
        let restored = Entropy::restore(
            EntropyConstructorArgs(guest_mem),
            &EntropyState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
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
