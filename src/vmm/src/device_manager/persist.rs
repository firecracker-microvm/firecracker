// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for saving/restoring the MMIO device manager and its devices.

// Currently only supports x86_64.
#![cfg(target_arch = "x86_64")]

use std::io;
use std::result::Result;
use std::sync::{Arc, Mutex};

use super::mmio::*;

use devices::virtio::block::persist::{BlockConstructorArgs, BlockState};
use devices::virtio::block::Block;
use devices::virtio::net::persist::{Error as NetError, NetConstructorArgs, NetState};
use devices::virtio::net::Net;
use devices::virtio::persist::{MmioTransportConstructorArgs, MmioTransportState};
use devices::virtio::vsock::persist::{VsockConstructorArgs, VsockState, VsockUdsConstructorArgs};
use devices::virtio::vsock::{Vsock, VsockError, VsockUnixBackend, VsockUnixBackendError};
use devices::virtio::{MmioTransport, VirtioDevice, TYPE_BLOCK, TYPE_NET, TYPE_VSOCK};
use kvm_ioctls::VmFd;
use polly::event_manager::{Error as EventMgrError, EventManager, Subscriber};
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::GuestMemoryMmap;

/// Errors for (de)serialization of the MMIO device manager.
#[derive(Debug)]
pub enum Error {
    Block(io::Error),
    EventManager(EventMgrError),
    DeviceManager(super::mmio::Error),
    MmioTransport,
    Net(NetError),
    Vsock(VsockError),
    VsockUnixBackend(VsockUnixBackendError),
}

#[derive(Versionize)]
/// Holds the state of a block device connected to the MMIO space.
pub struct ConnectedBlockState {
    /// Device identifier.
    pub device_id: String,
    /// Device state.
    pub device_state: BlockState,
    /// Mmio transport state.
    pub transport_state: MmioTransportState,
    /// VmmResources.
    pub mmio_slot: MMIODeviceInfo,
}

#[derive(Versionize)]
/// Holds the state of a net device connected to the MMIO space.
pub struct ConnectedNetState {
    /// Device identifier.
    pub device_id: String,
    /// Device state.
    pub device_state: NetState,
    /// Mmio transport state.
    pub transport_state: MmioTransportState,
    /// VmmResources.
    pub mmio_slot: MMIODeviceInfo,
}

#[derive(Versionize)]
/// Holds the state of a vsock device connected to the MMIO space.
pub struct ConnectedVsockState {
    /// Device identifier.
    pub device_id: String,
    /// Device state.
    pub device_state: VsockState,
    /// Mmio transport state.
    pub transport_state: MmioTransportState,
    /// VmmResources.
    pub mmio_slot: MMIODeviceInfo,
}

#[derive(Versionize)]
/// Holds the device states.
pub struct DeviceStates {
    /// Block device states.
    pub block_devices: Vec<ConnectedBlockState>,
    /// Net device states.
    pub net_devices: Vec<ConnectedNetState>,
    /// Vsock device state.
    pub vsock_device: Option<ConnectedVsockState>,
}

pub struct MMIODevManagerConstructorArgs<'a> {
    pub mem: GuestMemoryMmap,
    pub vm: &'a VmFd,
    pub event_manager: &'a mut EventManager,
}

impl<'a> Persist<'a> for MMIODeviceManager {
    type State = DeviceStates;
    type ConstructorArgs = MMIODevManagerConstructorArgs<'a>;
    type Error = Error;

    fn save(&self) -> Self::State {
        let mut states = DeviceStates {
            block_devices: Vec::new(),
            net_devices: Vec::new(),
            vsock_device: None,
        };
        let _: Result<(), ()> = self.for_each_device(|devtype, devid, devinfo, bus_dev| {
            if *devtype == arch::DeviceType::BootTimer {
                // No need to save BootTimer state.
                return Ok(());
            }

            let locked_bus_dev = bus_dev.lock().expect("Poisoned lock");
            let mmio_transport = locked_bus_dev
                .as_any()
                // Only MmioTransport implements BusDevice on x86_64 at this point.
                .downcast_ref::<MmioTransport>()
                .expect("Unexpected BusDevice type");

            let transport_state = mmio_transport.save();

            let locked_device = mmio_transport.locked_device();
            match locked_device.device_type() {
                TYPE_BLOCK => {
                    let block_state = locked_device
                        .as_any()
                        .downcast_ref::<Block>()
                        .unwrap()
                        .save();
                    states.block_devices.push(ConnectedBlockState {
                        device_id: devid.clone(),
                        device_state: block_state,
                        transport_state,
                        mmio_slot: devinfo.clone(),
                    });
                }
                TYPE_NET => {
                    let net_state = locked_device.as_any().downcast_ref::<Net>().unwrap().save();
                    states.net_devices.push(ConnectedNetState {
                        device_id: devid.clone(),
                        device_state: net_state,
                        transport_state,
                        mmio_slot: devinfo.clone(),
                    });
                }
                TYPE_VSOCK => {
                    let vsock = locked_device
                        .as_any()
                        // Currently, VsockUnixBackend is the only implementation of VsockBackend.
                        .downcast_ref::<Vsock<VsockUnixBackend>>()
                        .unwrap();
                    let vsock_state = VsockState {
                        backend: vsock.backend().save(),
                        frontend: vsock.save(),
                    };
                    states.vsock_device = Some(ConnectedVsockState {
                        device_id: devid.clone(),
                        device_state: vsock_state,
                        transport_state,
                        mmio_slot: devinfo.clone(),
                    });
                }
                _ => unreachable!(),
            };

            Ok(())
        });
        states
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut dev_manager =
            MMIODeviceManager::new(arch::MMIO_MEM_START, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mem = &constructor_args.mem;
        let vm = constructor_args.vm;

        let mut restore_helper = |device: Arc<Mutex<dyn VirtioDevice>>,
                                  as_subscriber: Arc<Mutex<dyn Subscriber>>,
                                  id: &String,
                                  state: &MmioTransportState,
                                  slot: &MMIODeviceInfo,
                                  event_manager: &mut EventManager|
         -> Result<(), Self::Error> {
            dev_manager
                .slot_sanity_check(slot)
                .map_err(Error::DeviceManager)?;

            let restore_args = MmioTransportConstructorArgs {
                mem: mem.clone(),
                device,
            };
            let mmio_transport =
                MmioTransport::restore(restore_args, state).map_err(|()| Error::MmioTransport)?;
            dev_manager
                .register_virtio_mmio_device(vm, id.clone(), mmio_transport, slot)
                .map_err(Error::DeviceManager)?;

            event_manager
                .add_subscriber(as_subscriber)
                .map_err(Error::EventManager)
        };

        for block_state in &state.block_devices {
            let device = Arc::new(Mutex::new(
                Block::restore(
                    BlockConstructorArgs { mem: mem.clone() },
                    &block_state.device_state,
                )
                .map_err(Error::Block)?,
            ));

            restore_helper(
                device.clone(),
                device.clone(),
                &block_state.device_id,
                &block_state.transport_state,
                &block_state.mmio_slot,
                constructor_args.event_manager,
            )?;

            // If device is activated, kick the block queue(s) to make up for any
            // pending or in-flight epoll events we may have not captured in snapshot.
            // No need to kick Ratelimiters because they are restored 'unblocked' so
            // any inflight `timer_fd` events can be safely discarded.
            let mut dev = device.lock().expect("Poisoned lock");
            if dev.is_activated() {
                dev.process_virtio_queues();
            }
        }
        for net_state in &state.net_devices {
            let device = Arc::new(Mutex::new(
                Net::restore(
                    NetConstructorArgs { mem: mem.clone() },
                    &net_state.device_state,
                )
                .map_err(Error::Net)?,
            ));

            restore_helper(
                device.clone(),
                device.clone(),
                &net_state.device_id,
                &net_state.transport_state,
                &net_state.mmio_slot,
                constructor_args.event_manager,
            )?;

            // If device is activated, kick the net queue(s) to make up for any
            // pending or in-flight epoll events we may have not captured in snapshot.
            // No need to kick Ratelimiters because they are restored 'unblocked' so
            // any inflight `timer_fd` events can be safely discarded.
            let mut dev = device.lock().expect("Poisoned lock");
            if dev.is_activated() {
                dev.process_virtio_queues();
            }
        }
        if let Some(vsock_state) = &state.vsock_device {
            let ctor_args = VsockUdsConstructorArgs {
                cid: vsock_state.device_state.frontend.cid,
            };
            let backend = VsockUnixBackend::restore(ctor_args, &vsock_state.device_state.backend)
                .map_err(Error::VsockUnixBackend)?;
            let device = Arc::new(Mutex::new(
                Vsock::restore(
                    VsockConstructorArgs {
                        mem: mem.clone(),
                        backend,
                    },
                    &vsock_state.device_state.frontend,
                )
                .map_err(Error::Vsock)?,
            ));

            restore_helper(
                device.clone(),
                device,
                &vsock_state.device_id,
                &vsock_state.transport_state,
                &vsock_state.mmio_slot,
                constructor_args.event_manager,
            )?;

            // Vsock has complicated protocol that isn't resilient to any packet loss,
            // so for Vsock we don't support connection persistence through snapshot.
            // Any in-flight packets or events are simply lost. Vsock is restored 'empty'.
        }

        Ok(dev_manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::tests::*;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::VsockDeviceConfig;
    use polly::event_manager::EventManager;
    use utils::tempfile::TempFile;

    impl PartialEq for ConnectedBlockState {
        fn eq(&self, other: &ConnectedBlockState) -> bool {
            // Actual device state equality is checked by the device's tests.
            self.transport_state == other.transport_state && self.mmio_slot == other.mmio_slot
        }
    }

    impl std::fmt::Debug for ConnectedBlockState {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "ConnectedBlockDevice {{ transport_state: {:?}, mmio_slot: {:?} }}",
                self.transport_state, self.mmio_slot
            )
        }
    }

    impl PartialEq for ConnectedNetState {
        fn eq(&self, other: &ConnectedNetState) -> bool {
            // Actual device state equality is checked by the device's tests.
            self.transport_state == other.transport_state && self.mmio_slot == other.mmio_slot
        }
    }

    impl std::fmt::Debug for ConnectedNetState {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "ConnectedNetDevice {{ transport_state: {:?}, mmio_slot: {:?} }}",
                self.transport_state, self.mmio_slot
            )
        }
    }

    impl PartialEq for ConnectedVsockState {
        fn eq(&self, other: &ConnectedVsockState) -> bool {
            // Actual device state equality is checked by the device's tests.
            self.transport_state == other.transport_state && self.mmio_slot == other.mmio_slot
        }
    }

    impl std::fmt::Debug for ConnectedVsockState {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "ConnectedVsockDevice {{ transport_state: {:?}, mmio_slot: {:?} }}",
                self.transport_state, self.mmio_slot
            )
        }
    }

    impl PartialEq for DeviceStates {
        fn eq(&self, other: &DeviceStates) -> bool {
            self.block_devices == other.block_devices
                && self.net_devices == other.net_devices
                && self.vsock_device == other.vsock_device
        }
    }

    impl std::fmt::Debug for DeviceStates {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "DevicesStates {{ block_devices: {:?}, net_devices: {:?}, vsock_device: {:?} }}",
                self.block_devices, self.net_devices, self.vsock_device
            )
        }
    }

    impl MMIODeviceManager {
        fn soft_clone(&self) -> Self {
            let dummy_mmio_base = 0;
            let dummy_irq_range = (0, 0);
            let mut clone = MMIODeviceManager::new(dummy_mmio_base, dummy_irq_range);
            // We only care about the device hashmap.
            clone.id_to_dev_info = self.id_to_dev_info.clone();
            clone
        }
    }

    impl PartialEq for MMIODeviceManager {
        fn eq(&self, other: &MMIODeviceManager) -> bool {
            // We only care about the device hashmap.
            if self.id_to_dev_info.len() != other.id_to_dev_info.len() {
                return false;
            }
            for (key, val) in &self.id_to_dev_info {
                match other.id_to_dev_info.get(key) {
                    Some(other_val) if val == other_val => continue,
                    _ => return false,
                };
            }
            true
        }
    }

    impl std::fmt::Debug for MMIODeviceManager {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{:?}", self.id_to_dev_info)
        }
    }

    #[test]
    fn test_device_manager_persistence() {
        let mut buf = vec![0; 16384];
        let version_map = VersionMap::new();
        // These need to survive so the restored blocks find them.
        let _block_files;
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        // Set up a vmm with one of each device, and get the serialized DeviceStates.
        let original_mmio_device_manager = {
            let mut event_manager = EventManager::new().expect("Unable to create EventManager");
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();

            // Add a block device.
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(drive_id, true, None, true)];
            _block_files =
                insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            // Add a net device.
            let network_interface = NetworkInterfaceConfig {
                iface_id: String::from("netif"),
                host_dev_name: String::from("hostname"),
                guest_mac: None,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
                allow_mmds_requests: true,
            };
            insert_net_device(
                &mut vmm,
                &mut cmdline,
                &mut event_manager,
                network_interface,
            );
            // Add a vsock device.
            let vsock_dev_id = "vsock";
            let vsock_config = VsockDeviceConfig {
                vsock_id: vsock_dev_id.to_string(),
                guest_cid: 3,
                uds_path: tmp_sock_file.as_path().to_str().unwrap().to_string(),
            };
            insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);

            vmm.mmio_device_manager
                .save()
                .serialize(&mut buf.as_mut_slice(), &version_map, 1)
                .unwrap();

            // We only want to keep the device map from the original MmioDeviceManager.
            vmm.mmio_device_manager.soft_clone()
        };
        tmp_sock_file.remove().unwrap();

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let vmm = default_vmm();
        let device_states: DeviceStates =
            DeviceStates::deserialize(&mut buf.as_slice(), &version_map, 1).unwrap();
        let restore_args = MMIODevManagerConstructorArgs {
            mem: vmm.guest_memory().clone(),
            vm: vmm.vm.fd(),
            event_manager: &mut event_manager,
        };
        let restored_dev_manager =
            MMIODeviceManager::restore(restore_args, &device_states).unwrap();

        assert_eq!(restored_dev_manager, original_mmio_device_manager);
    }
}
