// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring Virtio primitives.

use super::device::*;
use super::queue::*;
use crate::virtio::MmioTransport;
use crate::vm_memory::Address;
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use std::num::Wrapping;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Versionize)]
pub struct QueueState {
    /// The maximal size in elements offered by the device
    max_size: u16,

    /// The queue size in elements the driver selected
    size: u16,

    /// Indicates if the queue is finished with configuration
    ready: bool,

    /// Guest physical address of the descriptor table
    desc_table: u64,

    /// Guest physical address of the available ring
    avail_ring: u64,

    /// Guest physical address of the used ring
    used_ring: u64,

    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
}

impl Persist for Queue {
    type State = QueueState;
    type ConstructorArgs = ();
    type Error = ();

    fn save(&self) -> Self::State {
        QueueState {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: self.desc_table.0,
            avail_ring: self.avail_ring.0,
            used_ring: self.used_ring.0,
            next_avail: self.next_avail,
            next_used: self.next_used,
        }
    }

    fn restore(
        _: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(Queue {
            max_size: state.max_size,
            size: state.size,
            ready: state.ready,
            desc_table: GuestAddress::new(state.desc_table),
            avail_ring: GuestAddress::new(state.avail_ring),
            used_ring: GuestAddress::new(state.used_ring),
            next_avail: state.next_avail,
            next_used: state.next_used,
        })
    }
}

/// State of a VirtioDevice.
#[derive(Debug, PartialEq, Versionize)]
pub struct VirtioDeviceState {
    pub device_type: u32,
    pub avail_features: u64,
    pub acked_features: u64,
    pub queues: Vec<QueueState>,
    pub interrupt_status: usize,
    pub activated: bool,
}

impl VirtioDeviceState {
    pub fn from_device(device: &dyn VirtioDevice) -> Self {
        VirtioDeviceState {
            device_type: device.device_type(),
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            queues: device.queues().iter().map(Persist::save).collect(),
            interrupt_status: device.interrupt_status().load(Ordering::Relaxed),
            activated: device.is_activated(),
        }
    }
}

#[derive(Versionize)]
pub struct MmioTransportState {
    // The register where feature bits are stored.
    features_select: u32,
    // The register where features page is selected.
    acked_features_select: u32,
    queue_select: u32,
    device_status: u32,
    config_generation: u32,
}

pub struct MmioTransportConstructorArgs {
    mem: GuestMemoryMmap,
    device: Arc<Mutex<dyn VirtioDevice>>,
}

impl Persist for MmioTransport {
    type State = MmioTransportState;
    type ConstructorArgs = MmioTransportConstructorArgs;
    type Error = ();

    fn save(&self) -> Self::State {
        MmioTransportState {
            features_select: self.features_select,
            acked_features_select: self.acked_features_select,
            queue_select: self.queue_select,
            device_status: self.device_status,
            config_generation: self.config_generation,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut transport = MmioTransport::new(constructor_args.mem, constructor_args.device);
        transport.features_select = state.features_select;
        transport.acked_features_select = state.acked_features_select;
        transport.queue_select = state.queue_select;
        transport.device_status = state.device_status;
        transport.config_generation = state.config_generation;
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::block::device::tests::default_mem;
    use crate::virtio::mmio::tests::DummyDevice;

    use utils::tempfile::TempFile;

    #[test]
    fn test_queue_persistance() {
        let queue = Queue::new(128);

        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        queue
            .save()
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_queue = Queue::restore(
            (),
            &QueueState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        assert_eq!(restored_queue, queue);
    }

    #[test]
    fn test_virtio_device_state_versionize() {
        let dummy = DummyDevice::new();
        let mut mem = vec![0; 4096];
        let version_map = VersionMap::new();

        let state = VirtioDeviceState::from_device(&dummy);
        state
            .serialize(&mut mem.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_state =
            VirtioDeviceState::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap();
        assert_eq!(restored_state, state);
    }

    impl PartialEq for MmioTransport {
        fn eq(&self, other: &MmioTransport) -> bool {
            let self_dev_type = self.device().lock().unwrap().device_type();
            self.acked_features_select == other.acked_features_select &&
                self.features_select == other.features_select &&
                self.queue_select == other.queue_select &&
                self.device_status == other.device_status &&
                self.config_generation == other.config_generation &&
                self.interrupt_status.load(Ordering::SeqCst) == other.interrupt_status.load(Ordering::SeqCst) &&
                // Only checking equality of device type, actual device (de)ser is tested by that
                // device's tests.
                self_dev_type == other.device().lock().unwrap().device_type()
        }
    }

    fn generic_mmiotransport_persistance_test(
        mmio_transport: MmioTransport,
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) {
        let mut buf = vec![0; 4096];
        let version_map = VersionMap::new();

        mmio_transport
            .save()
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restore_args = MmioTransportConstructorArgs { mem, device };
        let restored_mmio_transport = MmioTransport::restore(
            restore_args,
            &MmioTransportState::deserialize(&mut buf.as_slice(), &version_map, 1).unwrap(),
        )
        .unwrap();

        assert_eq!(restored_mmio_transport, mmio_transport);
    }

    #[test]
    fn test_block_over_mmiotransport_persistance() {
        use crate::virtio::block::device::tests::default_block_with_path;
        let mem = default_mem();

        // Create backing file.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let block = default_block_with_path(f.as_path().to_str().unwrap().to_string());
        let block = Arc::new(Mutex::new(block));

        let mmio_transport = MmioTransport::new(mem.clone(), block.clone());
        generic_mmiotransport_persistance_test(mmio_transport, mem, block);
    }
}
