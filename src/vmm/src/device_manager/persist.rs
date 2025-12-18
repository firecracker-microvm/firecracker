// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for saving/restoring the MMIO device manager and its devices.

use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex};

use event_manager::{MutEventSubscriber, SubscriberOps};
use log::{error, warn};
use serde::{Deserialize, Serialize};

use super::acpi::ACPIDeviceManager;
use super::mmio::*;
#[cfg(target_arch = "aarch64")]
use crate::arch::DeviceType;
use crate::device_manager::acpi::ACPIDeviceError;
use crate::devices::acpi::vmclock::{VmClock, VmClockState};
use crate::devices::acpi::vmgenid::{VMGenIDState, VmGenId};
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::RTCDevice;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::balloon::persist::{BalloonConstructorArgs, BalloonState};
use crate::devices::virtio::balloon::{Balloon, BalloonError};
use crate::devices::virtio::block::BlockError;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::block::persist::{BlockConstructorArgs, BlockState};
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::generated::virtio_ids;
use crate::devices::virtio::mem::VirtioMem;
use crate::devices::virtio::mem::persist::{
    VirtioMemConstructorArgs, VirtioMemPersistError, VirtioMemState,
};
use crate::devices::virtio::net::Net;
use crate::devices::virtio::net::persist::{
    NetConstructorArgs, NetPersistError as NetError, NetState,
};
use crate::devices::virtio::persist::{MmioTransportConstructorArgs, MmioTransportState};
use crate::devices::virtio::pmem::device::Pmem;
use crate::devices::virtio::pmem::persist::{
    PmemConstructorArgs, PmemPersistError as PmemError, PmemState,
};
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::rng::persist::{
    EntropyConstructorArgs, EntropyPersistError as EntropyError, EntropyState,
};
use crate::devices::virtio::transport::mmio::{IrqTrigger, MmioTransport};
use crate::devices::virtio::vsock::persist::{
    VsockConstructorArgs, VsockState, VsockUdsConstructorArgs,
};
use crate::devices::virtio::vsock::{Vsock, VsockError, VsockUnixBackend, VsockUnixBackendError};
use crate::mmds::data_store::MmdsVersion;
use crate::resources::VmResources;
use crate::snapshot::Persist;
use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
use crate::vmm_config::mmds::MmdsConfigError;
use crate::vstate::bus::BusError;
use crate::vstate::memory::GuestMemoryMmap;
use crate::{EventManager, Vm};

/// Errors for (de)serialization of the MMIO device manager.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DevicePersistError {
    /// Balloon: {0}
    Balloon(#[from] BalloonError),
    /// Block: {0}
    Block(#[from] BlockError),
    /// Device manager: {0}
    DeviceManager(#[from] super::mmio::MmioError),
    /// Mmio transport
    MmioTransport,
    /// Bus error: {0}
    Bus(#[from] BusError),
    #[cfg(target_arch = "aarch64")]
    /// Legacy: {0}
    Legacy(#[from] std::io::Error),
    /// Net: {0}
    Net(#[from] NetError),
    /// Vsock: {0}
    Vsock(#[from] VsockError),
    /// VsockUnixBackend: {0}
    VsockUnixBackend(#[from] VsockUnixBackendError),
    /// MmdsConfig: {0}
    MmdsConfig(#[from] MmdsConfigError),
    /// Entropy: {0}
    Entropy(#[from] EntropyError),
    /// Pmem: {0}
    Pmem(#[from] PmemError),
    /// virtio-mem: {0}
    VirtioMem(#[from] VirtioMemPersistError),
    /// Could not activate device: {0}
    DeviceActivation(#[from] ActivateError),
}

/// Holds the state of a MMIO VirtIO device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioDeviceState<T> {
    /// Device identifier.
    pub device_id: String,
    /// Device state.
    pub device_state: T,
    /// Mmio transport state.
    pub transport_state: MmioTransportState,
    /// VmmResources.
    pub device_info: MMIODeviceInfo,
}

/// Holds the state of a legacy device connected to the MMIO space.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedLegacyState {
    /// Device identifier.
    pub type_: DeviceType,
    /// VmmResources.
    pub device_info: MMIODeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdsState {
    pub version: MmdsVersion,
    pub imds_compat: bool,
}

/// Holds the device states.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DeviceStates {
    #[cfg(target_arch = "aarch64")]
    // State of legacy devices in MMIO space.
    pub legacy_devices: Vec<ConnectedLegacyState>,
    /// Block device states.
    pub block_devices: Vec<VirtioDeviceState<BlockState>>,
    /// Net device states.
    pub net_devices: Vec<VirtioDeviceState<NetState>>,
    /// Vsock device state.
    pub vsock_device: Option<VirtioDeviceState<VsockState>>,
    /// Balloon device state.
    pub balloon_device: Option<VirtioDeviceState<BalloonState>>,
    /// Mmds version.
    pub mmds: Option<MmdsState>,
    /// Entropy device state.
    pub entropy_device: Option<VirtioDeviceState<EntropyState>>,
    /// Pmem device states.
    pub pmem_devices: Vec<VirtioDeviceState<PmemState>>,
    /// Memory device state.
    pub memory_device: Option<VirtioDeviceState<VirtioMemState>>,
}

pub struct MMIODevManagerConstructorArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: &'a Arc<Vm>,
    pub event_manager: &'a mut EventManager,
    pub vm_resources: &'a mut VmResources,
    pub instance_id: &'a str,
}
impl fmt::Debug for MMIODevManagerConstructorArgs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MMIODevManagerConstructorArgs")
            .field("mem", &self.mem)
            .field("vm", &self.vm)
            .field("event_manager", &"?")
            .field("for_each_restored_device", &"?")
            .field("vm_resources", &self.vm_resources)
            .field("instance_id", &self.instance_id)
            .finish()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ACPIDeviceManagerState {
    vmgenid: VMGenIDState,
    vmclock: VmClockState,
}

impl<'a> Persist<'a> for ACPIDeviceManager {
    type State = ACPIDeviceManagerState;
    type ConstructorArgs = &'a Vm;
    type Error = ACPIDeviceError;

    fn save(&self) -> Self::State {
        ACPIDeviceManagerState {
            vmgenid: self.vmgenid.save(),
            vmclock: self.vmclock.save(),
        }
    }

    fn restore(vm: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let acpi_devices = ACPIDeviceManager {
            // Safe to unwrap() here, this will never return an error.
            vmgenid: VmGenId::restore((), &state.vmgenid).unwrap(),
            // Safe to unwrap() here, this will never return an error.
            vmclock: VmClock::restore((), &state.vmclock).unwrap(),
        };

        vm.register_irq(
            &acpi_devices.vmclock.interrupt_evt,
            acpi_devices.vmclock.gsi,
        )?;

        acpi_devices.attach_vmgenid(vm)?;
        Ok(acpi_devices)
    }
}

impl<'a> Persist<'a> for MMIODeviceManager {
    type State = DeviceStates;
    type ConstructorArgs = MMIODevManagerConstructorArgs<'a>;
    type Error = DevicePersistError;

    fn save(&self) -> Self::State {
        let mut states = DeviceStates::default();

        #[cfg(target_arch = "aarch64")]
        {
            if let Some(device) = &self.serial {
                states.legacy_devices.push(ConnectedLegacyState {
                    type_: DeviceType::Serial,
                    device_info: device.resources,
                });
            }

            if let Some(device) = &self.rtc {
                states.legacy_devices.push(ConnectedLegacyState {
                    type_: DeviceType::Rtc,
                    device_info: device.resources,
                });
            }
        }

        let _: Result<(), ()> = self.for_each_virtio_device(|_, devid, device| {
            let mmio_transport_locked = device.inner.lock().expect("Poisoned lock");
            let transport_state = mmio_transport_locked.save();
            let device_info = device.resources;
            let device_id = devid.clone();

            let mut locked_device = mmio_transport_locked.locked_device();
            match locked_device.device_type() {
                virtio_ids::VIRTIO_ID_BALLOON => {
                    let device_state = locked_device
                        .as_any()
                        .downcast_ref::<Balloon>()
                        .unwrap()
                        .save();
                    states.balloon_device = Some(VirtioDeviceState {
                        device_id,
                        device_state,
                        transport_state,
                        device_info,
                    });
                }
                // Both virtio-block and vhost-user-block share same device type.
                virtio_ids::VIRTIO_ID_BLOCK => {
                    let block = locked_device.as_mut_any().downcast_mut::<Block>().unwrap();
                    if block.is_vhost_user() {
                        warn!(
                            "Skipping vhost-user-block device. VhostUserBlock does not support \
                             snapshotting yet"
                        );
                    } else {
                        block.prepare_save();
                        let device_state = block.save();
                        states.block_devices.push(VirtioDeviceState {
                            device_id,
                            device_state,
                            transport_state,
                            device_info,
                        });
                    }
                }
                virtio_ids::VIRTIO_ID_NET => {
                    let net = locked_device.as_mut_any().downcast_mut::<Net>().unwrap();
                    if let (Some(mmds_ns), None) = (net.mmds_ns.as_ref(), states.mmds.as_ref()) {
                        let mmds_guard = mmds_ns.mmds.lock().expect("Poisoned lock");
                        states.mmds = Some(MmdsState {
                            version: mmds_guard.version(),
                            imds_compat: mmds_guard.imds_compat(),
                        });
                    }

                    net.prepare_save();
                    let device_state = net.save();
                    states.net_devices.push(VirtioDeviceState {
                        device_id,
                        device_state,
                        transport_state,
                        device_info,
                    });
                }
                virtio_ids::VIRTIO_ID_VSOCK => {
                    let vsock = locked_device
                        .as_mut_any()
                        // Currently, VsockUnixBackend is the only implementation of VsockBackend.
                        .downcast_mut::<Vsock<VsockUnixBackend>>()
                        .unwrap();

                    // Send Transport event to reset connections if device
                    // is activated.
                    if vsock.is_activated() {
                        vsock.send_transport_reset_event().unwrap_or_else(|err| {
                            error!("Failed to send reset transport event: {:?}", err);
                        });
                    }

                    // Save state after potential notification to the guest. This
                    // way we save changes to the queue the notification can cause.
                    let device_state = VsockState {
                        backend: vsock.backend().save(),
                        frontend: vsock.save(),
                    };

                    states.vsock_device = Some(VirtioDeviceState {
                        device_id,
                        device_state,
                        transport_state,
                        device_info,
                    });
                }
                virtio_ids::VIRTIO_ID_RNG => {
                    let entropy = locked_device
                        .as_mut_any()
                        .downcast_mut::<Entropy>()
                        .unwrap();
                    let device_state = entropy.save();

                    states.entropy_device = Some(VirtioDeviceState {
                        device_id,
                        device_state,
                        transport_state,
                        device_info,
                    });
                }
                virtio_ids::VIRTIO_ID_PMEM => {
                    let pmem = locked_device.as_mut_any().downcast_mut::<Pmem>().unwrap();
                    let device_state = pmem.save();
                    states.pmem_devices.push(VirtioDeviceState {
                        device_id,
                        device_state,
                        transport_state,
                        device_info,
                    })
                }
                virtio_ids::VIRTIO_ID_MEM => {
                    let mem = locked_device
                        .as_mut_any()
                        .downcast_mut::<VirtioMem>()
                        .unwrap();
                    let device_state = mem.save();

                    states.memory_device = Some(VirtioDeviceState {
                        device_id,
                        device_state,
                        transport_state,
                        device_info,
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
        let mut dev_manager = MMIODeviceManager::new();
        let mem = constructor_args.mem;
        let vm = constructor_args.vm;

        #[cfg(target_arch = "aarch64")]
        {
            for state in &state.legacy_devices {
                if state.type_ == DeviceType::Serial {
                    let serial = crate::DeviceManager::setup_serial_device(
                        constructor_args.event_manager,
                        constructor_args.vm_resources.serial_out_path.as_ref(),
                    )?;

                    dev_manager.register_mmio_serial(vm, serial, Some(state.device_info))?;
                }
                if state.type_ == DeviceType::Rtc {
                    let rtc = Arc::new(Mutex::new(RTCDevice::new()));
                    dev_manager.register_mmio_rtc(vm, rtc, Some(state.device_info))?;
                }
            }
        }

        let mut restore_helper = |device: Arc<Mutex<dyn VirtioDevice>>,
                                  activated: bool,
                                  is_vhost_user: bool,
                                  as_subscriber: Arc<Mutex<dyn MutEventSubscriber>>,
                                  id: &String,
                                  state: &MmioTransportState,
                                  device_info: &MMIODeviceInfo,
                                  event_manager: &mut EventManager|
         -> Result<(), Self::Error> {
            let interrupt = Arc::new(IrqTrigger::new());
            let restore_args = MmioTransportConstructorArgs {
                mem: mem.clone(),
                interrupt: interrupt.clone(),
                device: device.clone(),
                is_vhost_user,
            };
            let mmio_transport = Arc::new(Mutex::new(
                MmioTransport::restore(restore_args, state)
                    .map_err(|()| DevicePersistError::MmioTransport)?,
            ));

            dev_manager.register_mmio_virtio(
                vm,
                id.clone(),
                MMIODevice {
                    resources: *device_info,
                    inner: mmio_transport,
                },
            )?;

            if activated {
                device
                    .lock()
                    .expect("Poisoned lock")
                    .activate(mem.clone(), interrupt)?;
            }

            event_manager.add_subscriber(as_subscriber);
            Ok(())
        };

        if let Some(balloon_state) = &state.balloon_device {
            let device = Arc::new(Mutex::new(Balloon::restore(
                BalloonConstructorArgs { mem: mem.clone() },
                &balloon_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .balloon
                .set_device(device.clone());

            restore_helper(
                device.clone(),
                balloon_state.device_state.virtio_state.activated,
                false,
                device,
                &balloon_state.device_id,
                &balloon_state.transport_state,
                &balloon_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        for block_state in &state.block_devices {
            let device = Arc::new(Mutex::new(Block::restore(
                BlockConstructorArgs { mem: mem.clone() },
                &block_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .block
                .add_virtio_device(device.clone());

            restore_helper(
                device.clone(),
                block_state.device_state.is_activated(),
                false,
                device,
                &block_state.device_id,
                &block_state.transport_state,
                &block_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        // Initialize MMDS if MMDS state is included.
        if let Some(mmds) = &state.mmds {
            constructor_args.vm_resources.set_mmds_basic_config(
                mmds.version,
                mmds.imds_compat,
                constructor_args.instance_id,
            )?;
        }

        for net_state in &state.net_devices {
            let device = Arc::new(Mutex::new(Net::restore(
                NetConstructorArgs {
                    mem: mem.clone(),
                    mmds: constructor_args
                        .vm_resources
                        .mmds
                        .as_ref()
                        // Clone the Arc reference.
                        .cloned(),
                },
                &net_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .net_builder
                .add_device(device.clone());

            restore_helper(
                device.clone(),
                net_state.device_state.virtio_state.activated,
                false,
                device,
                &net_state.device_id,
                &net_state.transport_state,
                &net_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        if let Some(vsock_state) = &state.vsock_device {
            let ctor_args = VsockUdsConstructorArgs {
                cid: vsock_state.device_state.frontend.cid,
            };
            let backend = VsockUnixBackend::restore(ctor_args, &vsock_state.device_state.backend)?;
            let device = Arc::new(Mutex::new(Vsock::restore(
                VsockConstructorArgs {
                    mem: mem.clone(),
                    backend,
                },
                &vsock_state.device_state.frontend,
            )?));

            constructor_args
                .vm_resources
                .vsock
                .set_device(device.clone());

            restore_helper(
                device.clone(),
                vsock_state.device_state.frontend.virtio_state.activated,
                false,
                device,
                &vsock_state.device_id,
                &vsock_state.transport_state,
                &vsock_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        if let Some(entropy_state) = &state.entropy_device {
            let ctor_args = EntropyConstructorArgs { mem: mem.clone() };

            let device = Arc::new(Mutex::new(Entropy::restore(
                ctor_args,
                &entropy_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .entropy
                .set_device(device.clone());

            restore_helper(
                device.clone(),
                entropy_state.device_state.virtio_state.activated,
                false,
                device,
                &entropy_state.device_id,
                &entropy_state.transport_state,
                &entropy_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        for pmem_state in &state.pmem_devices {
            let device = Arc::new(Mutex::new(Pmem::restore(
                PmemConstructorArgs {
                    mem,
                    vm: vm.as_ref(),
                },
                &pmem_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .pmem
                .add_device(device.clone());

            restore_helper(
                device.clone(),
                pmem_state.device_state.virtio_state.activated,
                false,
                device,
                &pmem_state.device_id,
                &pmem_state.transport_state,
                &pmem_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        if let Some(memory_state) = &state.memory_device {
            let ctor_args = VirtioMemConstructorArgs::new(Arc::clone(vm));
            let device = VirtioMem::restore(ctor_args, &memory_state.device_state)?;

            constructor_args.vm_resources.memory_hotplug = Some(MemoryHotplugConfig {
                total_size_mib: device.total_size_mib(),
                block_size_mib: device.block_size_mib(),
                slot_size_mib: device.slot_size_mib(),
            });

            let arcd_device = Arc::new(Mutex::new(device));

            restore_helper(
                arcd_device.clone(),
                memory_state.device_state.virtio_state.activated,
                false,
                arcd_device,
                &memory_state.device_id,
                &memory_state.transport_state,
                &memory_state.device_info,
                constructor_args.event_manager,
            )?;
        }

        Ok(dev_manager)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::builder::tests::*;
    use crate::device_manager;
    use crate::devices::virtio::block::CacheType;
    use crate::resources::VmmConfig;
    use crate::snapshot::Snapshot;
    use crate::vmm_config::balloon::BalloonDeviceConfig;
    use crate::vmm_config::entropy::EntropyDeviceConfig;
    use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::pmem::PmemConfig;
    use crate::vmm_config::vsock::VsockDeviceConfig;

    impl<T> PartialEq for VirtioDeviceState<T> {
        fn eq(&self, other: &VirtioDeviceState<T>) -> bool {
            // Actual device state equality is checked by the device's tests.
            self.transport_state == other.transport_state && self.device_info == other.device_info
        }
    }

    impl PartialEq for DeviceStates {
        fn eq(&self, other: &DeviceStates) -> bool {
            self.balloon_device == other.balloon_device
                && self.block_devices == other.block_devices
                && self.net_devices == other.net_devices
                && self.vsock_device == other.vsock_device
                && self.entropy_device == other.entropy_device
                && self.memory_device == other.memory_device
        }
    }

    impl<T> PartialEq for MMIODevice<T> {
        fn eq(&self, other: &Self) -> bool {
            self.resources == other.resources
        }
    }

    impl PartialEq for MMIODeviceManager {
        fn eq(&self, other: &MMIODeviceManager) -> bool {
            // We only care about the device hashmap.
            if self.virtio_devices.len() != other.virtio_devices.len() {
                return false;
            }
            for (key, val) in &self.virtio_devices {
                match other.virtio_devices.get(key) {
                    Some(other_val) if val == other_val => continue,
                    _ => return false,
                }
            }

            self.boot_timer == other.boot_timer
        }
    }

    #[test]
    fn test_device_manager_persistence() {
        let mut buf = vec![0; 65536];
        // These need to survive so the restored blocks find them.
        let _block_files;
        let _pmem_files;
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        // Set up a vmm with one of each device, and get the serialized DeviceStates.
        {
            let mut event_manager = EventManager::new().expect("Unable to create EventManager");
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();

            // Add a balloon device.
            let balloon_cfg = BalloonDeviceConfig {
                amount_mib: 123,
                deflate_on_oom: false,
                stats_polling_interval_s: 1,
                free_page_hinting: false,
                free_page_reporting: false,
            };
            insert_balloon_device(&mut vmm, &mut cmdline, &mut event_manager, balloon_cfg);
            // Add a block device.
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id,
                true,
                None,
                true,
                CacheType::Unsafe,
            )];
            _block_files =
                insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            // Add a net device.
            let network_interface = NetworkInterfaceConfig {
                iface_id: String::from("netif"),
                host_dev_name: String::from("hostname"),
                guest_mac: None,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            };
            insert_net_device_with_mmds(
                &mut vmm,
                &mut cmdline,
                &mut event_manager,
                network_interface,
                MmdsVersion::V2,
            );
            // Add a vsock device.
            let vsock_dev_id = "vsock";
            let vsock_config = VsockDeviceConfig {
                vsock_id: Some(vsock_dev_id.to_string()),
                guest_cid: 3,
                uds_path: tmp_sock_file.as_path().to_str().unwrap().to_string(),
            };
            insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);
            // Add an entropy device.
            let entropy_config = EntropyDeviceConfig::default();
            insert_entropy_device(&mut vmm, &mut cmdline, &mut event_manager, entropy_config);
            // Add a pmem device.
            let pmem_id = String::from("pmem");
            let pmem_configs = vec![PmemConfig {
                id: pmem_id,
                path_on_host: "".into(),
                root_device: true,
                read_only: true,
            }];
            _pmem_files =
                insert_pmem_devices(&mut vmm, &mut cmdline, &mut event_manager, pmem_configs);

            let memory_hotplug_config = MemoryHotplugConfig {
                total_size_mib: 1024,
                block_size_mib: 2,
                slot_size_mib: 128,
            };
            insert_virtio_mem_device(
                &mut vmm,
                &mut cmdline,
                &mut event_manager,
                memory_hotplug_config,
            );

            Snapshot::new(vmm.device_manager.save())
                .save(&mut buf.as_mut_slice())
                .unwrap();
        }

        tmp_sock_file.remove().unwrap();

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let vmm = default_vmm();
        let device_manager_state: device_manager::DevicesState =
            Snapshot::load_without_crc_check(buf.as_slice())
                .unwrap()
                .data;
        let vm_resources = &mut VmResources::default();
        let restore_args = MMIODevManagerConstructorArgs {
            mem: vmm.vm.guest_memory(),
            vm: &vmm.vm,
            event_manager: &mut event_manager,
            vm_resources,
            instance_id: "microvm-id",
        };
        let _restored_dev_manager =
            MMIODeviceManager::restore(restore_args, &device_manager_state.mmio_state).unwrap();

        let expected_vm_resources = format!(
            r#"{{
  "balloon": {{
    "amount_mib": 123,
    "deflate_on_oom": false,
    "stats_polling_interval_s": 1,
    "free_page_hinting": false,
    "free_page_reporting": false
  }},
  "drives": [
    {{
      "drive_id": "root",
      "partuuid": null,
      "is_root_device": true,
      "cache_type": "Unsafe",
      "is_read_only": true,
      "path_on_host": "{}",
      "rate_limiter": null,
      "io_engine": "Sync",
      "socket": null
    }}
  ],
  "boot-source": {{
    "kernel_image_path": "",
    "initrd_path": null,
    "boot_args": null
  }},
  "cpu-config": null,
  "logger": null,
  "machine-config": {{
    "vcpu_count": 1,
    "mem_size_mib": 128,
    "smt": false,
    "track_dirty_pages": false,
    "huge_pages": "None"
  }},
  "metrics": null,
  "mmds-config": {{
    "version": "V2",
    "network_interfaces": [
      "netif"
    ],
    "ipv4_address": "169.254.169.254",
    "imds_compat": false
  }},
  "network-interfaces": [
    {{
      "iface_id": "netif",
      "host_dev_name": "hostname",
      "guest_mac": null,
      "rx_rate_limiter": null,
      "tx_rate_limiter": null
    }}
  ],
  "vsock": {{
    "guest_cid": 3,
    "uds_path": "{}"
  }},
  "entropy": {{
    "rate_limiter": null
  }},
  "pmem": [
    {{
      "id": "pmem",
      "path_on_host": "{}",
      "root_device": true,
      "read_only": true
    }}
  ],
  "memory-hotplug": {{
    "total_size_mib": 1024,
    "block_size_mib": 2,
    "slot_size_mib": 128
  }}
}}"#,
            _block_files.last().unwrap().as_path().to_str().unwrap(),
            tmp_sock_file.as_path().to_str().unwrap(),
            _pmem_files.last().unwrap().as_path().to_str().unwrap(),
        );

        assert_eq!(
            vm_resources
                .mmds
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .version(),
            MmdsVersion::V2
        );
        assert_eq!(
            device_manager_state.mmio_state.mmds.unwrap().version,
            MmdsVersion::V2
        );
        assert_eq!(
            expected_vm_resources,
            serde_json::to_string_pretty(&VmmConfig::from(&*vm_resources)).unwrap()
        );
    }
}
