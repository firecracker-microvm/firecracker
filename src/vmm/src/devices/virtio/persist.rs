// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring Virtio primitives.

use std::num::Wrapping;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::queue::{InvalidAvailIdx, QueueError};
use super::transport::mmio::IrqTrigger;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::mmio::MmioTransport;
use crate::snapshot::Persist;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

/// Errors thrown during restoring virtio state.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PersistError {
    /// Snapshot state contains invalid queue info.
    InvalidInput,
    /// Could not restore queue: {0}
    QueueConstruction(QueueError),
    /// {0}
    InvalidAvailIdx(#[from] InvalidAvailIdx),
}

/// Queue information saved in snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

    /// The number of added used buffers since last guest kick
    num_added: Wrapping<u16>,
}

/// Auxiliary structure for restoring queues.
#[derive(Debug, Clone)]
pub struct QueueConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// Is device this queue belong to activated
    pub is_activated: bool,
}

impl Persist<'_> for Queue {
    type State = QueueState;
    type ConstructorArgs = QueueConstructorArgs;
    type Error = QueueError;

    fn save(&self) -> Self::State {
        QueueState {
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            desc_table: self.desc_table_address.0,
            avail_ring: self.avail_ring_address.0,
            used_ring: self.used_ring_address.0,
            next_avail: self.next_avail,
            next_used: self.next_used,
            num_added: self.num_added,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut queue = Queue {
            max_size: state.max_size,
            size: state.size,
            ready: state.ready,
            desc_table_address: GuestAddress(state.desc_table),
            avail_ring_address: GuestAddress(state.avail_ring),
            used_ring_address: GuestAddress(state.used_ring),

            desc_table_ptr: std::ptr::null(),
            avail_ring_ptr: std::ptr::null_mut(),
            used_ring_ptr: std::ptr::null_mut(),

            next_avail: state.next_avail,
            next_used: state.next_used,
            uses_notif_suppression: false,
            num_added: state.num_added,
        };
        if constructor_args.is_activated {
            queue.initialize(&constructor_args.mem)?;
        }
        Ok(queue)
    }
}

/// State of a VirtioDevice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtioDeviceState {
    /// Device type.
    pub device_type: VirtioDeviceType,
    /// Available virtio features.
    pub avail_features: u64,
    /// Negotiated virtio features.
    pub acked_features: u64,
    /// List of queues.
    pub queues: Vec<QueueState>,
    /// Flag for activated status.
    pub activated: bool,
}

impl VirtioDeviceState {
    /// Construct the virtio state of a device.
    pub fn from_device(device: &dyn VirtioDevice) -> Self {
        VirtioDeviceState {
            device_type: device.device_type(),
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            queues: device.queues().iter().map(Persist::save).collect(),
            activated: device.is_activated(),
        }
    }

    /// Does sanity checking on the `self` state against expected values
    /// and builds queues from state.
    pub fn build_queues_checked(
        &self,
        mem: &GuestMemoryMmap,
        expected_device_type: VirtioDeviceType,
        expected_num_queues: usize,
        expected_queue_max_size: u16,
    ) -> Result<Vec<Queue>, PersistError> {
        // Sanity check:
        // - right device type,
        // - acked features is a subset of available ones,
        // - right number of queues,
        if self.device_type != expected_device_type
            || (self.acked_features & !self.avail_features) != 0
            || self.queues.len() != expected_num_queues
        {
            return Err(PersistError::InvalidInput);
        }

        let uses_notif_suppression = (self.acked_features & (1u64 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        let queue_construction_args = QueueConstructorArgs {
            mem: mem.clone(),
            is_activated: self.activated,
        };
        let queues: Vec<Queue> = self
            .queues
            .iter()
            .map(|queue_state| {
                Queue::restore(queue_construction_args.clone(), queue_state)
                    .map(|mut queue| {
                        if uses_notif_suppression {
                            queue.enable_notif_suppression();
                        }
                        queue
                    })
                    .map_err(PersistError::QueueConstruction)
            })
            .collect::<Result<_, _>>()?;

        for q in &queues {
            // Sanity check queue size and queue max size.
            if q.max_size != expected_queue_max_size {
                return Err(PersistError::InvalidInput);
            }
        }
        Ok(queues)
    }
}

/// Transport information saved in snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmioTransportState {
    // The register where feature bits are stored.
    features_select: u32,
    // The register where features page is selected.
    acked_features_select: u32,
    queue_select: u32,
    device_status: u32,
    config_generation: u32,
    interrupt_status: u32,
}

/// Auxiliary structure for initializing the transport when resuming from a snapshot.
#[derive(Debug)]
pub struct MmioTransportConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// Interrupt to use for the device
    pub interrupt: Arc<IrqTrigger>,
    /// Device associated with the current MMIO state.
    pub device: Arc<Mutex<dyn VirtioDevice>>,
    /// Is device backed by vhost-user.
    pub is_vhost_user: bool,
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
            interrupt_status: self.interrupt.irq_status.load(Ordering::SeqCst),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut transport = MmioTransport::new(
            constructor_args.mem,
            constructor_args.interrupt,
            constructor_args.device,
            constructor_args.is_vhost_user,
        );
        transport.features_select = state.features_select;
        transport.acked_features_select = state.acked_features_select;
        transport.queue_select = state.queue_select;
        transport.device_status = state.device_status;
        transport.config_generation = state.config_generation;
        transport
            .interrupt
            .irq_status
            .store(state.interrupt_status, Ordering::SeqCst);
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::VirtioBlock;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::block::virtio::test_utils::default_block_with_path;
    use crate::devices::virtio::net::Net;
    use crate::devices::virtio::net::test_utils::default_net;
    use crate::devices::virtio::test_utils::default_mem;
    use crate::devices::virtio::transport::mmio::tests::DummyDevice;
    use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};

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
                num_added: Wrapping(0),
            }
        }
    }

    #[test]
    fn test_virtiodev_sanity_checks() {
        let max_size = DEFAULT_QUEUE_MAX_SIZE;
        let mut state = VirtioDeviceState {
            device_type: VirtioDeviceType::Net,
            avail_features: 0,
            acked_features: 0,
            queues: vec![],
            activated: false,
        };
        let mem = default_mem();
        // Valid checks.
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, 0, max_size)
            .unwrap();
        // Invalid dev-type.
        state
            .build_queues_checked(&mem, VirtioDeviceType::Block, 0, max_size)
            .unwrap_err();
        // Invalid num-queues.
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, 1, max_size)
            .unwrap_err();
        // Unavailable features acked.
        state.acked_features = 1;
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, 0, max_size)
            .unwrap_err();

        // Validate queue sanity checks.
        let mut state = VirtioDeviceState {
            device_type: VirtioDeviceType::Net,
            avail_features: 0,
            acked_features: 0,
            queues: vec![],
            activated: false,
        };
        let good_q = QueueState::default();
        state.queues = vec![good_q];
        // Valid.
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, state.queues.len(), max_size)
            .unwrap();

        // Invalid max queue size.
        let bad_q = QueueState {
            max_size: max_size + 1,
            ..Default::default()
        };
        state.queues = vec![bad_q];
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, state.queues.len(), max_size)
            .unwrap_err();

        // Invalid: size > max.
        let bad_q = QueueState {
            size: max_size + 1,
            ..Default::default()
        };
        state.queues = vec![bad_q];
        state.activated = true;
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, state.queues.len(), max_size)
            .unwrap_err();

        // activated && !q.is_valid()
        let bad_q = QueueState::default();
        state.queues = vec![bad_q];
        state.activated = true;
        state
            .build_queues_checked(&mem, VirtioDeviceType::Net, state.queues.len(), max_size)
            .unwrap_err();
    }

    #[test]
    fn test_queue_persistence() {
        let mem = default_mem();

        let mut queue = Queue::new(128);
        queue.ready = true;
        queue.size = queue.max_size;
        queue.initialize(&mem).unwrap();

        let queue_state = queue.save();
        let serialized_data = bitcode::serialize(&queue_state).unwrap();

        let ca = QueueConstructorArgs {
            mem,
            is_activated: true,
        };
        let restored_state = bitcode::deserialize(&serialized_data).unwrap();
        let restored_queue = Queue::restore(ca, &restored_state).unwrap();

        assert_eq!(restored_queue, queue);
    }

    #[test]
    fn test_virtio_device_state_serde() {
        let dummy = DummyDevice::new();

        let state = VirtioDeviceState::from_device(&dummy);
        let serialized_data = bitcode::serialize(&state).unwrap();

        let restored_state: VirtioDeviceState = bitcode::deserialize(&serialized_data).unwrap();
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
                self.interrupt.irq_status.load(Ordering::SeqCst) == other.interrupt.irq_status.load(Ordering::SeqCst) &&
                // Only checking equality of device type, actual device (de)ser is tested by that
                // device's tests.
                self_dev_type == other.device().lock().unwrap().device_type()
        }
    }

    fn generic_mmiotransport_persistence_test(
        mmio_transport: MmioTransport,
        interrupt: Arc<IrqTrigger>,
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) {
        let transport_state = mmio_transport.save();
        let serialized_data = bitcode::serialize(&transport_state).unwrap();

        let restore_args = MmioTransportConstructorArgs {
            mem,
            interrupt,
            device,
            is_vhost_user: false,
        };
        let restored_state = bitcode::deserialize(&serialized_data).unwrap();
        let restored_mmio_transport =
            MmioTransport::restore(restore_args, &restored_state).unwrap();

        assert_eq!(restored_mmio_transport, mmio_transport);
    }

    fn create_default_block() -> (
        MmioTransport,
        Arc<IrqTrigger>,
        GuestMemoryMmap,
        Arc<Mutex<VirtioBlock>>,
    ) {
        let mem = default_mem();
        let interrupt = Arc::new(IrqTrigger::new());

        // Create backing file.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let block = default_block_with_path(
            f.as_path().to_str().unwrap().to_string(),
            FileEngineType::default(),
        );
        let block = Arc::new(Mutex::new(block));
        let mmio_transport =
            MmioTransport::new(mem.clone(), interrupt.clone(), block.clone(), false);

        (mmio_transport, interrupt, mem, block)
    }

    fn create_default_net() -> (
        MmioTransport,
        Arc<IrqTrigger>,
        GuestMemoryMmap,
        Arc<Mutex<Net>>,
    ) {
        let mem = default_mem();
        let interrupt = Arc::new(IrqTrigger::new());
        let net = Arc::new(Mutex::new(default_net()));
        let mmio_transport = MmioTransport::new(mem.clone(), interrupt.clone(), net.clone(), false);

        (mmio_transport, interrupt, mem, net)
    }

    fn default_vsock() -> (
        MmioTransport,
        Arc<IrqTrigger>,
        GuestMemoryMmap,
        Arc<Mutex<Vsock<VsockUnixBackend>>>,
    ) {
        let mem = default_mem();
        let interrupt = Arc::new(IrqTrigger::new());

        let guest_cid = 52;
        let mut temp_uds_path = TempFile::new().unwrap();
        // Remove the file so the path can be used by the socket.
        temp_uds_path.remove().unwrap();
        let uds_path = String::from(temp_uds_path.as_path().to_str().unwrap());
        let backend = VsockUnixBackend::new(guest_cid, uds_path).unwrap();
        let vsock = Vsock::new(guest_cid, backend).unwrap();
        let vsock = Arc::new(Mutex::new(vsock));
        let mmio_transport =
            MmioTransport::new(mem.clone(), interrupt.clone(), vsock.clone(), false);

        (mmio_transport, interrupt, mem, vsock)
    }

    #[test]
    fn test_block_over_mmiotransport_persistence() {
        let (mmio_transport, interrupt, mem, block) = create_default_block();
        generic_mmiotransport_persistence_test(mmio_transport, interrupt, mem, block);
    }

    #[test]
    fn test_net_over_mmiotransport_persistence() {
        let (mmio_transport, interrupt, mem, net) = create_default_net();
        generic_mmiotransport_persistence_test(mmio_transport, interrupt, mem, net);
    }

    #[test]
    fn test_vsock_over_mmiotransport_persistence() {
        let (mmio_transport, interrupt, mem, vsock) = default_vsock();
        generic_mmiotransport_persistence_test(mmio_transport, interrupt, mem, vsock);
    }
}
