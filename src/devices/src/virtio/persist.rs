// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring Virtio primitives.

use super::device::*;
use super::queue::*;
use crate::virtio::MmioTransport;
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::Address;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use std::num::Wrapping;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub enum Error {
    InvalidInput,
}

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

impl QueueState {
    /// Does a sanity check against expected values.
    pub fn sanity_check(&self, queue_max_size: u16) -> std::result::Result<(), Error> {
        // Cannot use `q.is_valid()` because snapshot can happen at any time,
        // including during device configuration/activation when fields are only
        // partially configured.
        // We can't even check if GuestAddresses are valid guest phys addresses because
        // their configuration happens in two steps for the two u32 halves of the
        // u64 address. This means a snapshot can capture them only partially configured.
        //
        // The best we can do is sanity check queue size and max size.
        if self.max_size != queue_max_size || self.size > queue_max_size {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
}

impl Persist<'_> for Queue {
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

    /// Does a sanity check against expected values.
    pub fn sanity_check(
        &self,
        device_type: u32,
        num_queues: usize,
        queue_max_size: u16,
    ) -> std::result::Result<(), Error> {
        // Check:
        // - right device type,
        // - acked features is a subset of available ones,
        // - right number of queues,
        if self.device_type != device_type
            || (self.acked_features & !self.avail_features) != 0
            || self.queues.len() != num_queues
        {
            return Err(Error::InvalidInput);
        }
        // Queues are the expected size.
        for q in self.queues.iter() {
            q.sanity_check(queue_max_size)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Versionize)]
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
    pub mem: GuestMemoryMmap,
    pub device: Arc<Mutex<dyn VirtioDevice>>,
}

impl Persist<'_> for MmioTransport {
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
    use crate::virtio::{Block, Net, Vsock, VsockUnixBackend};

    use utils::tempfile::TempFile;

    const DEFAULT_QUEUE_MAX_SIZE: u16 = 256;
    impl Default for QueueState {
        fn default() -> QueueState {
            QueueState {
                max_size: DEFAULT_QUEUE_MAX_SIZE,
                size: DEFAULT_QUEUE_MAX_SIZE,
                ready: false,
                desc_table: 0,
                avail_ring: 0,
                used_ring: 0,
                next_avail: Wrapping(0),
                next_used: Wrapping(0),
            }
        }
    }

    impl Default for VirtioDeviceState {
        fn default() -> VirtioDeviceState {
            VirtioDeviceState {
                device_type: 0,
                avail_features: 0,
                acked_features: 0,
                queues: vec![],
                interrupt_status: 0,
                activated: false,
            }
        }
    }

    #[test]
    fn test_queue_sanity_checks() {
        let max_size = DEFAULT_QUEUE_MAX_SIZE;
        let good_q = QueueState::default();
        // Valid.
        good_q.sanity_check(max_size).unwrap();

        // Invalid max queue size.
        let mut bad_q = QueueState::default();
        bad_q.max_size = max_size + 1;
        bad_q.sanity_check(max_size).unwrap_err();

        // Invalid: size > max.
        let mut bad_q = QueueState::default();
        bad_q.size = max_size + 1;
        bad_q.sanity_check(max_size).unwrap_err();
    }

    #[test]
    fn test_virtiodev_sanity_checks() {
        let max_size = DEFAULT_QUEUE_MAX_SIZE;
        let mut state = VirtioDeviceState::default();
        // Valid checks.
        state.sanity_check(0, 0, max_size).unwrap();
        // Invalid dev-type.
        state.sanity_check(1, 0, max_size).unwrap_err();
        // Invalid num-queues.
        state.sanity_check(0, 1, max_size).unwrap_err();
        // Unavailable features acked.
        state.acked_features = 1;
        state.sanity_check(0, 0, max_size).unwrap_err();
    }

    #[test]
    fn test_queue_persistence() {
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

    fn generic_mmiotransport_persistence_test(
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

    fn default_block() -> (MmioTransport, GuestMemoryMmap, Arc<Mutex<Block>>) {
        use crate::virtio::block::device::tests::default_block_with_path;
        let mem = default_mem();

        // Create backing file.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let block = default_block_with_path(f.as_path().to_str().unwrap().to_string());
        let block = Arc::new(Mutex::new(block));
        let mmio_transport = MmioTransport::new(mem.clone(), block.clone());

        (mmio_transport, mem, block)
    }

    fn default_net() -> (MmioTransport, GuestMemoryMmap, Arc<Mutex<Net>>) {
        let mem = default_mem();
        let net = Arc::new(Mutex::new(Net::default_net()));
        let mmio_transport = MmioTransport::new(mem.clone(), net.clone());

        (mmio_transport, mem, net)
    }

    fn default_vsock() -> (
        MmioTransport,
        GuestMemoryMmap,
        Arc<Mutex<Vsock<VsockUnixBackend>>>,
    ) {
        let mem = default_mem();

        let guest_cid = 52;
        let mut temp_uds_path = TempFile::new().unwrap();
        // Remove the file so the path can be used by the socket.
        temp_uds_path.remove().unwrap();
        let uds_path = String::from(temp_uds_path.as_path().to_str().unwrap());
        let backend = VsockUnixBackend::new(guest_cid, uds_path).unwrap();
        let vsock = Vsock::new(guest_cid, backend).unwrap();
        let vsock = Arc::new(Mutex::new(vsock));
        let mmio_transport = MmioTransport::new(mem.clone(), vsock.clone());

        (mmio_transport, mem, vsock)
    }

    #[test]
    fn test_block_over_mmiotransport_persistence() {
        let (mmio_transport, mem, block) = default_block();
        generic_mmiotransport_persistence_test(mmio_transport, mem, block);
    }

    #[test]
    fn test_net_over_mmiotransport_persistence() {
        let (mmio_transport, mem, net) = default_net();
        generic_mmiotransport_persistence_test(mmio_transport, mem, net);
    }

    #[test]
    fn test_vsock_over_mmiotransport_persistence() {
        let (mmio_transport, mem, vsock) = default_vsock();
        generic_mmiotransport_persistence_test(mmio_transport, mem, vsock);
    }
}
