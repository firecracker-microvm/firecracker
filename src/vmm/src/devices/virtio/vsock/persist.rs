// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state and support structures for persisting Vsock devices and backends.

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use serde::{Deserialize, Serialize};

use super::*;
use crate::devices::virtio::device::DeviceState;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::vsock::TYPE_VSOCK;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

/// The Vsock serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockState {
    /// The vsock backend state.
    pub backend: VsockBackendState,
    /// The vsock frontend state.
    pub frontend: VsockFrontendState,
}

/// The Vsock frontend serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockFrontendState {
    /// Context IDentifier.
    pub cid: u64,
    virtio_state: VirtioDeviceState,
}

/// An enum for the serializable backend state types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VsockBackendState {
    /// UDS backend state.
    Uds(VsockUdsState),
}

/// The Vsock Unix Backend serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockUdsState {
    /// The path for the UDS socket.
    pub(crate) path: String,
}

/// A helper structure that holds the constructor arguments for VsockUnixBackend
#[derive(Debug)]
pub struct VsockConstructorArgs<B> {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// The vsock Unix Backend.
    pub backend: B,
}

/// A helper structure that holds the constructor arguments for VsockUnixBackend
#[derive(Debug)]
pub struct VsockUdsConstructorArgs {
    /// cid available in VsockFrontendState.
    pub cid: u64,
}

impl Persist<'_> for VsockUnixBackend {
    type State = VsockBackendState;
    type ConstructorArgs = VsockUdsConstructorArgs;
    type Error = VsockUnixBackendError;

    fn save(&self) -> Self::State {
        VsockBackendState::Uds(VsockUdsState {
            path: self.host_sock_path.clone(),
        })
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        match state {
            VsockBackendState::Uds(uds_state) => Ok(VsockUnixBackend::new(
                constructor_args.cid,
                uds_state.path.clone(),
            )?),
        }
    }
}

impl<B> Persist<'_> for Vsock<B>
where
    B: VsockBackend + 'static + Debug,
{
    type State = VsockFrontendState;
    type ConstructorArgs = VsockConstructorArgs<B>;
    type Error = VsockError;

    fn save(&self) -> Self::State {
        VsockFrontendState {
            cid: self.cid(),
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // Restore queues.
        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                TYPE_VSOCK,
                defs::VSOCK_NUM_QUEUES,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(VsockError::VirtioState)?;
        let mut vsock = Self::with_queues(state.cid, constructor_args.backend, queues)?;

        vsock.acked_features = state.virtio_state.acked_features;
        vsock.avail_features = state.virtio_state.avail_features;
        vsock.irq_trigger.irq_status =
            Arc::new(AtomicU32::new(state.virtio_state.interrupt_status));
        vsock.device_state = if state.virtio_state.activated {
            DeviceState::Activated(constructor_args.mem)
        } else {
            DeviceState::Inactive
        };
        Ok(vsock)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::device::AVAIL_FEATURES;
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::vsock::defs::uapi;
    use crate::devices::virtio::vsock::test_utils::{TestBackend, TestContext};
    use crate::snapshot::Snapshot;
    use crate::utils::byte_order;

    impl Persist<'_> for TestBackend {
        type State = VsockBackendState;
        type ConstructorArgs = VsockUdsConstructorArgs;
        type Error = VsockUnixBackendError;

        fn save(&self) -> Self::State {
            VsockBackendState::Uds(VsockUdsState {
                path: "test".to_owned(),
            })
        }

        fn restore(_: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
            match state {
                VsockBackendState::Uds(_) => Ok(TestBackend::new()),
            }
        }
    }

    #[test]
    fn test_persist_uds_backend() {
        let ctx = TestContext::new();
        let device_features = AVAIL_FEATURES;
        let driver_features: u64 = AVAIL_FEATURES | 1 | (1 << 32);
        let device_pages = [
            (device_features & 0xffff_ffff) as u32,
            (device_features >> 32) as u32,
        ];
        let driver_pages = [
            (driver_features & 0xffff_ffff) as u32,
            (driver_features >> 32) as u32,
        ];

        // Test serialization
        let mut mem = vec![0; 4096];

        // Save backend and device state separately.
        let state = VsockState {
            backend: ctx.device.backend().save(),
            frontend: ctx.device.save(),
        };

        Snapshot::serialize(&mut mem.as_mut_slice(), &state).unwrap();

        let restored_state: VsockState = Snapshot::deserialize(&mut mem.as_slice()).unwrap();
        let mut restored_device = Vsock::restore(
            VsockConstructorArgs {
                mem: ctx.mem.clone(),
                backend: match restored_state.backend {
                    VsockBackendState::Uds(uds_state) => {
                        assert_eq!(uds_state.path, "test".to_owned());
                        TestBackend::new()
                    }
                },
            },
            &restored_state.frontend,
        )
        .unwrap();

        assert_eq!(restored_device.device_type(), uapi::VIRTIO_ID_VSOCK);
        assert_eq!(restored_device.avail_features_by_page(0), device_pages[0]);
        assert_eq!(restored_device.avail_features_by_page(1), device_pages[1]);
        assert_eq!(restored_device.avail_features_by_page(2), 0);

        restored_device.ack_features_by_page(0, driver_pages[0]);
        restored_device.ack_features_by_page(1, driver_pages[1]);
        restored_device.ack_features_by_page(2, 0);
        restored_device.ack_features_by_page(0, !driver_pages[0]);
        assert_eq!(
            restored_device.acked_features(),
            device_features & driver_features
        );

        // Test reading 32-bit chunks.
        let mut data = [0u8; 8];
        restored_device.read_config(0, &mut data[..4]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[..])),
            ctx.cid & 0xffff_ffff
        );
        restored_device.read_config(4, &mut data[4..]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[4..])),
            (ctx.cid >> 32) & 0xffff_ffff
        );

        // Test reading 64-bit.
        let mut data = [0u8; 8];
        restored_device.read_config(0, &mut data);
        assert_eq!(byte_order::read_le_u64(&data), ctx.cid);

        // Check that out-of-bounds reading doesn't mutate the destination buffer.
        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        restored_device.read_config(2, &mut data);
        assert_eq!(data, [0u8, 1, 2, 3, 4, 5, 6, 7]);
    }
}
