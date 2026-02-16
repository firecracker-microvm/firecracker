// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use event_manager::{MutEventSubscriber, SubscriberOps};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};

use super::persist::MmdsState;
use crate::devices::pci::PciSegment;
use crate::devices::virtio::balloon::Balloon;
use crate::devices::virtio::balloon::persist::{BalloonConstructorArgs, BalloonState};
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::block::persist::{BlockConstructorArgs, BlockState};
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::mem::VirtioMem;
use crate::devices::virtio::mem::persist::{VirtioMemConstructorArgs, VirtioMemState};
use crate::devices::virtio::net::Net;
use crate::devices::virtio::net::persist::{NetConstructorArgs, NetState};
use crate::devices::virtio::pmem::device::Pmem;
use crate::devices::virtio::pmem::persist::{PmemConstructorArgs, PmemState};
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::rng::persist::{EntropyConstructorArgs, EntropyState};
use crate::devices::virtio::transport::pci::device::{
    CAPABILITY_BAR_SIZE, VirtioPciDevice, VirtioPciDeviceError, VirtioPciDeviceState,
};
use crate::devices::virtio::vsock::persist::{
    VsockConstructorArgs, VsockState, VsockUdsConstructorArgs,
};
use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};
use crate::pci::bus::PciRootError;
use crate::resources::VmResources;
use crate::snapshot::Persist;
use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
use crate::vmm_config::mmds::MmdsConfigError;
use crate::vstate::bus::BusError;
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::GuestMemoryMmap;
use crate::{EventManager, Vm};

#[derive(Debug, Default)]
pub struct PciDevices {
    /// PCIe segment of the VMM, if PCI is enabled. We currently support a single PCIe segment.
    pub pci_segment: Option<PciSegment>,
    /// All VirtIO PCI devices of the system
    pub virtio_devices: HashMap<(VirtioDeviceType, String), Arc<Mutex<VirtioPciDevice>>>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciManagerError {
    /// Resource allocation error: {0}
    ResourceAllocation(#[from] vm_allocator::Error),
    /// Bus error: {0}
    Bus(#[from] BusError),
    /// PCI root error: {0}
    PciRoot(#[from] PciRootError),
    /// MSI error: {0}
    Msi(#[from] InterruptError),
    /// VirtIO PCI device error: {0}
    VirtioPciDevice(#[from] VirtioPciDeviceError),
    /// KVM error: {0}
    Kvm(#[from] vmm_sys_util::errno::Error),
    /// MMDS error: {0}
    Mmds(#[from] MmdsConfigError),
}

impl PciDevices {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn attach_pci_segment(&mut self, vm: &Arc<Vm>) -> Result<(), PciManagerError> {
        // We only support a single PCIe segment. Calling this function twice is a Firecracker
        // internal error.
        assert!(self.pci_segment.is_none());

        // Currently we don't assign any IRQs to PCI devices. We will be using MSI-X interrupts
        // only.
        let pci_segment = PciSegment::new(0, vm, &[0u8; 32])?;
        self.pci_segment = Some(pci_segment);

        Ok(())
    }

    fn register_bars_with_bus(
        vm: &Vm,
        virtio_device: &Arc<Mutex<VirtioPciDevice>>,
    ) -> Result<(), PciManagerError> {
        let virtio_device_locked = virtio_device.lock().expect("Poisoned lock");

        debug!(
            "Inserting MMIO BAR region: {:#x}:{:#x}",
            virtio_device_locked.bar_address, CAPABILITY_BAR_SIZE
        );
        vm.common.mmio_bus.insert(
            virtio_device.clone(),
            virtio_device_locked.bar_address,
            CAPABILITY_BAR_SIZE,
        )?;

        Ok(())
    }

    pub(crate) fn attach_pci_virtio_device<
        T: 'static + VirtioDevice + MutEventSubscriber + Debug,
    >(
        &mut self,
        vm: &Arc<Vm>,
        id: String,
        device: Arc<Mutex<T>>,
    ) -> Result<(), PciManagerError> {
        // We should only be reaching this point if PCI is enabled
        let pci_segment = self.pci_segment.as_ref().unwrap();
        let pci_device_bdf = pci_segment.next_device_bdf()?;
        debug!("Allocating BDF: {pci_device_bdf:?} for device");
        let mem = vm.guest_memory().clone();

        let device_type = device.lock().expect("Poisoned lock").device_type();

        // Allocate one MSI vector per queue, plus one for configuration
        let msix_num =
            u16::try_from(device.lock().expect("Poisoned lock").queues().len() + 1).unwrap();

        let msix_vectors = Vm::create_msix_group(vm.clone(), msix_num)?;

        // Create the transport
        let mut virtio_device = VirtioPciDevice::new(
            id.clone(),
            mem,
            device,
            Arc::new(msix_vectors),
            pci_device_bdf.into(),
        )?;

        // Allocate bars
        let mut resource_allocator_lock = vm.resource_allocator();
        let resource_allocator = resource_allocator_lock.deref_mut();

        virtio_device.allocate_bars(&mut resource_allocator.mmio64_memory);

        let virtio_device = Arc::new(Mutex::new(virtio_device));
        pci_segment
            .pci_bus
            .lock()
            .expect("Poisoned lock")
            .add_device(pci_device_bdf.device() as u32, virtio_device.clone());

        self.virtio_devices
            .insert((device_type, id.clone()), virtio_device.clone());

        Self::register_bars_with_bus(vm, &virtio_device)?;
        virtio_device
            .lock()
            .expect("Poisoned lock")
            .register_notification_ioevent(vm)?;

        Ok(())
    }

    fn restore_pci_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        vm: &Arc<Vm>,
        device: Arc<Mutex<T>>,
        device_id: &str,
        transport_state: &VirtioPciDeviceState,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        // We should only be reaching this point if PCI is enabled
        let pci_segment = self.pci_segment.as_ref().unwrap();
        let device_type = device.lock().expect("Poisoned lock").device_type();

        let virtio_device = Arc::new(Mutex::new(VirtioPciDevice::new_from_state(
            device_id.to_string(),
            vm,
            device.clone(),
            transport_state.clone(),
        )?));

        pci_segment
            .pci_bus
            .lock()
            .expect("Poisoned lock")
            .add_device(
                transport_state.pci_device_bdf.device() as u32,
                virtio_device.clone(),
            );

        self.virtio_devices
            .insert((device_type, device_id.to_string()), virtio_device.clone());

        Self::register_bars_with_bus(vm, &virtio_device)?;
        virtio_device
            .lock()
            .expect("Poisoned lock")
            .register_notification_ioevent(vm)?;

        event_manager.add_subscriber(device);

        Ok(())
    }

    /// Gets the specified device.
    pub fn get_virtio_device(
        &self,
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<&Arc<Mutex<VirtioPciDevice>>> {
        self.virtio_devices
            .get(&(device_type, device_id.to_string()))
    }

    pub fn for_each_virtio_device(&self, mut f: impl FnMut(VirtioDeviceType, &dyn VirtioDevice)) {
        for ((device_type, _), pci_device) in &self.virtio_devices {
            let device_arc = pci_device.lock().expect("Poisoned lock").virtio_device();
            let device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &*device);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioDeviceState<T> {
    /// Device identifier
    pub device_id: String,
    /// Device BDF
    pub pci_device_bdf: u32,
    /// Device state
    pub device_state: T,
    /// Transport state
    pub transport_state: VirtioPciDeviceState,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PciDevicesState {
    /// Whether PCI is enabled
    pub pci_enabled: bool,
    /// Block device states.
    pub block_devices: Vec<VirtioDeviceState<BlockState>>,
    /// Net device states.
    pub net_devices: Vec<VirtioDeviceState<NetState>>,
    /// Vsock device state.
    pub vsock_device: Option<VirtioDeviceState<VsockState>>,
    /// Balloon device state.
    pub balloon_device: Option<VirtioDeviceState<BalloonState>>,
    /// Mmds state.
    pub mmds: Option<MmdsState>,
    /// Entropy device state.
    pub entropy_device: Option<VirtioDeviceState<EntropyState>>,
    /// Pmem device states.
    pub pmem_devices: Vec<VirtioDeviceState<PmemState>>,
    /// Memory device state.
    pub memory_device: Option<VirtioDeviceState<VirtioMemState>>,
}

pub struct PciDevicesConstructorArgs<'a> {
    pub vm: &'a Arc<Vm>,
    pub mem: &'a GuestMemoryMmap,
    pub vm_resources: &'a mut VmResources,
    pub instance_id: &'a str,
    pub event_manager: &'a mut EventManager,
}

impl<'a> Debug for PciDevicesConstructorArgs<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PciDevicesConstructorArgs")
            .field("vm", &self.vm)
            .field("mem", &self.mem)
            .field("vm_resources", &self.vm_resources)
            .field("instance_id", &self.instance_id)
            .finish()
    }
}

impl<'a> Persist<'a> for PciDevices {
    type State = PciDevicesState;
    type ConstructorArgs = PciDevicesConstructorArgs<'a>;
    type Error = PciManagerError;

    fn save(&self) -> Self::State {
        let mut state = PciDevicesState::default();
        if self.pci_segment.is_some() {
            state.pci_enabled = true;
        } else {
            return state;
        }

        for pci_dev in self.virtio_devices.values() {
            let locked_pci_dev = pci_dev.lock().expect("Poisoned lock");
            let virtio_dev = locked_pci_dev.virtio_device();
            // We need to call `prepare_save()` on the device before saving the transport
            // so that, if we modify the transport state while preparing the device, e.g. sending
            // an interrupt to the guest, this is correctly captured in the saved transport state.
            let mut locked_virtio_dev = virtio_dev.lock().expect("Poisoned lock");
            locked_virtio_dev.prepare_save();
            let transport_state = locked_pci_dev.state();

            let pci_device_bdf = transport_state.pci_device_bdf.into();

            match locked_virtio_dev.device_type() {
                VirtioDeviceType::Balloon => {
                    let balloon_device = locked_virtio_dev
                        .as_any()
                        .downcast_ref::<Balloon>()
                        .unwrap();

                    let device_state = balloon_device.save();

                    state.balloon_device = Some(VirtioDeviceState {
                        device_id: balloon_device.id().to_string(),
                        pci_device_bdf,
                        device_state,
                        transport_state,
                    });
                }
                VirtioDeviceType::Block => {
                    let block_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Block>()
                        .unwrap();
                    if block_dev.is_vhost_user() {
                        warn!(
                            "Skipping vhost-user-block device. VhostUserBlock does not support \
                             snapshotting yet"
                        );
                    } else {
                        let device_state = block_dev.save();
                        state.block_devices.push(VirtioDeviceState {
                            device_id: block_dev.id().to_string(),
                            pci_device_bdf,
                            device_state,
                            transport_state,
                        });
                    }
                }
                VirtioDeviceType::Net => {
                    let net_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Net>()
                        .unwrap();
                    if let (Some(mmds_ns), None) = (net_dev.mmds_ns.as_ref(), state.mmds.as_ref()) {
                        let mmds_guard = mmds_ns.mmds.lock().expect("Poisoned lock");
                        state.mmds = Some(MmdsState {
                            version: mmds_guard.version(),
                            imds_compat: mmds_guard.imds_compat(),
                        });
                    }
                    let device_state = net_dev.save();

                    state.net_devices.push(VirtioDeviceState {
                        device_id: net_dev.id().to_string(),
                        pci_device_bdf,
                        device_state,
                        transport_state,
                    })
                }
                VirtioDeviceType::Vsock => {
                    let vsock_dev = locked_virtio_dev
                        .as_mut_any()
                        // Currently, VsockUnixBackend is the only implementation of VsockBackend.
                        .downcast_mut::<Vsock<VsockUnixBackend>>()
                        .unwrap();

                    // Send Transport event to reset connections if device
                    // is activated.
                    if vsock_dev.is_activated() {
                        vsock_dev
                            .send_transport_reset_event()
                            .unwrap_or_else(|err| {
                                error!("Failed to send reset transport event: {:?}", err);
                            });
                    }

                    // Save state after potential notification to the guest. This
                    // way we save changes to the queue the notification can cause.
                    let vsock_state = VsockState {
                        backend: vsock_dev.backend().save(),
                        frontend: vsock_dev.save(),
                    };

                    state.vsock_device = Some(VirtioDeviceState {
                        device_id: vsock_dev.id().to_string(),
                        pci_device_bdf,
                        device_state: vsock_state,
                        transport_state,
                    });
                }
                VirtioDeviceType::Rng => {
                    let rng_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Entropy>()
                        .unwrap();
                    let device_state = rng_dev.save();

                    state.entropy_device = Some(VirtioDeviceState {
                        device_id: rng_dev.id().to_string(),
                        pci_device_bdf,
                        device_state,
                        transport_state,
                    })
                }
                VirtioDeviceType::Pmem => {
                    let pmem_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Pmem>()
                        .unwrap();
                    let device_state = pmem_dev.save();
                    state.pmem_devices.push(VirtioDeviceState {
                        device_id: pmem_dev.config.id.clone(),
                        pci_device_bdf,
                        device_state,
                        transport_state,
                    });
                }
                VirtioDeviceType::Mem => {
                    let mem_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<VirtioMem>()
                        .unwrap();
                    let device_state = mem_dev.save();

                    state.memory_device = Some(VirtioDeviceState {
                        device_id: mem_dev.id().to_string(),
                        pci_device_bdf,
                        device_state,
                        transport_state,
                    })
                }
            }
        }

        state
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mem = constructor_args.mem;
        let mut pci_devices = PciDevices::new();
        if !state.pci_enabled {
            return Ok(pci_devices);
        }

        pci_devices.attach_pci_segment(constructor_args.vm)?;

        if let Some(balloon_state) = &state.balloon_device {
            let device = Arc::new(Mutex::new(
                Balloon::restore(
                    BalloonConstructorArgs { mem: mem.clone() },
                    &balloon_state.device_state,
                )
                .unwrap(),
            ));

            constructor_args
                .vm_resources
                .balloon
                .set_device(device.clone());

            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    device,
                    &balloon_state.device_id,
                    &balloon_state.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        for block_state in &state.block_devices {
            let device = Arc::new(Mutex::new(
                Block::restore(
                    BlockConstructorArgs { mem: mem.clone() },
                    &block_state.device_state,
                )
                .unwrap(),
            ));

            constructor_args
                .vm_resources
                .block
                .add_virtio_device(device.clone());

            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    device,
                    &block_state.device_id,
                    &block_state.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        // Initialize MMDS if MMDS state is included.
        if let Some(mmds) = &state.mmds {
            constructor_args
                .vm_resources
                .set_mmds_basic_config(mmds.version, mmds.imds_compat, constructor_args.instance_id)
                .unwrap();
        } else if state
            .net_devices
            .iter()
            .any(|dev| dev.device_state.mmds_ns.is_some())
        {
            // If there's at least one network device having an mmds_ns, it means
            // that we are restoring from a version that did not persist the `MmdsVersionState`.
            // Init with the default.
            constructor_args.vm_resources.mmds_or_default()?;
        }

        for net_state in &state.net_devices {
            let device = Arc::new(Mutex::new(
                Net::restore(
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
                )
                .unwrap(),
            ));

            constructor_args
                .vm_resources
                .net_builder
                .add_device(device.clone());

            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    device,
                    &net_state.device_id,
                    &net_state.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        if let Some(vsock_state) = &state.vsock_device {
            let ctor_args = VsockUdsConstructorArgs {
                cid: vsock_state.device_state.frontend.cid,
            };
            let backend =
                VsockUnixBackend::restore(ctor_args, &vsock_state.device_state.backend).unwrap();
            let device = Arc::new(Mutex::new(
                Vsock::restore(
                    VsockConstructorArgs {
                        mem: mem.clone(),
                        backend,
                    },
                    &vsock_state.device_state.frontend,
                )
                .unwrap(),
            ));

            constructor_args
                .vm_resources
                .vsock
                .set_device(device.clone());

            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    device,
                    &vsock_state.device_id,
                    &vsock_state.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        if let Some(entropy_state) = &state.entropy_device {
            let ctor_args = EntropyConstructorArgs { mem: mem.clone() };

            let device = Arc::new(Mutex::new(
                Entropy::restore(ctor_args, &entropy_state.device_state).unwrap(),
            ));

            constructor_args
                .vm_resources
                .entropy
                .set_device(device.clone());

            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    device,
                    &entropy_state.device_id,
                    &entropy_state.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        for pmem_state in &state.pmem_devices {
            let device = Arc::new(Mutex::new(
                Pmem::restore(
                    PmemConstructorArgs {
                        mem,
                        vm: constructor_args.vm.as_ref(),
                    },
                    &pmem_state.device_state,
                )
                .unwrap(),
            ));

            constructor_args
                .vm_resources
                .pmem
                .add_device(device.clone());

            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    device,
                    &pmem_state.device_id,
                    &pmem_state.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        if let Some(memory_device) = &state.memory_device {
            let ctor_args = VirtioMemConstructorArgs::new(Arc::clone(constructor_args.vm));
            let device = VirtioMem::restore(ctor_args, &memory_device.device_state).unwrap();

            constructor_args.vm_resources.memory_hotplug = Some(MemoryHotplugConfig {
                total_size_mib: device.total_size_mib(),
                block_size_mib: device.block_size_mib(),
                slot_size_mib: device.slot_size_mib(),
            });

            let arcd_device = Arc::new(Mutex::new(device));
            pci_devices
                .restore_pci_device(
                    constructor_args.vm,
                    arcd_device,
                    &memory_device.device_id,
                    &memory_device.transport_state,
                    constructor_args.event_manager,
                )
                .unwrap()
        }

        Ok(pci_devices)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::builder::tests::*;
    use crate::device_manager;
    use crate::devices::virtio::block::CacheType;
    use crate::mmds::data_store::MmdsVersion;
    use crate::resources::VmmConfig;
    use crate::vmm_config::balloon::BalloonDeviceConfig;
    use crate::vmm_config::entropy::EntropyDeviceConfig;
    use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::pmem::PmemConfig;
    use crate::vmm_config::vsock::VsockDeviceConfig;

    #[test]
    fn test_device_manager_persistence() {
        // These need to survive so the restored blocks find them.
        let _block_files;
        let _pmem_files;
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();

        let serialized_data;
        // Set up a vmm with one of each device, and get the serialized DeviceStates.
        {
            let mut event_manager = EventManager::new().expect("Unable to create EventManager");
            let mut vmm = default_vmm();
            vmm.device_manager.enable_pci(&vmm.vm).unwrap();
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

            let device_state = vmm.device_manager.save();
            serialized_data = bitcode::serialize(&device_state).unwrap();
        }

        tmp_sock_file.remove().unwrap();

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        // Keep in mind we are re-creating here an empty DeviceManager. Restoring later on
        // will create a new PciDevices manager different than vmm.pci_devices. We're doing
        // this to avoid restoring the whole Vmm, since what we really need from Vmm is the Vm
        // object and calling default_vmm() is the easiest way to create one.
        let vmm = default_vmm();
        let device_manager_state: device_manager::DevicesState =
            bitcode::deserialize(&serialized_data).unwrap();
        let vm_resources = &mut VmResources::default();
        let restore_args = PciDevicesConstructorArgs {
            vm: &vmm.vm,
            mem: vmm.vm.guest_memory(),
            vm_resources,
            instance_id: "microvm-id",
            event_manager: &mut event_manager,
        };
        let _restored_dev_manager =
            PciDevices::restore(restore_args, &device_manager_state.pci_state).unwrap();

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
            device_manager_state.pci_state.mmds.unwrap().version,
            MmdsVersion::V2
        );
        assert_eq!(
            expected_vm_resources,
            serde_json::to_string_pretty(&VmmConfig::from(&*vm_resources)).unwrap()
        );
    }
}
