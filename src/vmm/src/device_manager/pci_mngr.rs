// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::sync::{Arc, Mutex};

use event_manager::{MutEventSubscriber, SubscriberOps};
use serde::{Deserialize, Serialize};

use super::persist::MmdsState;
use crate::EventManager;
use crate::device_manager::DevicePersistError;
use crate::devices::pci::PciSegment;
use crate::devices::vfio::VfioContext;
use crate::devices::vfio::VfioError;
use crate::devices::vfio::pci::{BarRequirement, BarSlot, BarWindow, VfioPciDevice, VfioPciError};
use crate::devices::virtio::balloon::Balloon;
use crate::devices::virtio::balloon::persist::{BalloonConstructorArgs, BalloonState};
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::block::persist::{BlockConstructorArgs, BlockState};
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceId, VirtioDeviceType};
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
use crate::logger::{debug, warn};
use crate::pci::PciSBDF;
use crate::pci::bus::PciBusError;
use crate::resources::VmResources;
use crate::snapshot::Persist;
use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
use crate::vstate::bus::BusError;
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::KvmVm;

#[derive(Debug)]
pub struct PciDevices {
    /// PCIe segment of the VMM. We currently support a single PCIe segment.
    pub pci_segment: PciSegment,
    /// All VirtIO PCI devices of the system
    pub virtio_devices: HashMap<VirtioDeviceId, Arc<Mutex<VirtioPciDevice>>>,
    /// All VFIO passthrough PCI devices of the system, keyed by their Firecracker id.
    pub vfio_devices: HashMap<String, Arc<Mutex<VfioPciDevice>>>,
    /// The IOMMU context shared by the VFIO devices, if any is attached.
    pub vfio_context: Option<VfioContext>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciManagerError {
    /// Resource allocation error: {0}
    ResourceAllocation(#[from] vm_allocator::Error),
    /// Bus error: {0}
    Bus(#[from] BusError),
    /// PCI bus error: {0}
    PciBus(#[from] PciBusError),
    /// MSI error: {0}
    Msi(#[from] InterruptError),
    /// VirtIO PCI device error: {0}
    VirtioPciDevice(#[from] VirtioPciDeviceError),
    /// KVM error: {0}
    Kvm(#[from] vmm_sys_util::errno::Error),
    /// VFIO error: {0}
    Vfio(#[from] VfioError),
    /// VFIO PCI device error: {0}
    VfioPci(#[from] VfioPciError),
}

impl PciDevices {
    pub fn new(vm: &Arc<KvmVm>) -> Result<Self, PciManagerError> {
        // No slot has an INTx route yet: virtio-pci devices use MSI-X only, and the routes of the
        // passthrough devices with an interrupt pin are set when they are attached.
        let pci_segment = PciSegment::new(0, vm, &[0u8; 32])?;

        Ok(Self {
            pci_segment,
            virtio_devices: HashMap::new(),
            vfio_devices: HashMap::new(),
            vfio_context: None,
        })
    }

    fn attach_common(
        &mut self,
        vm: &KvmVm,
        device_type: VirtioDeviceType,
        id: String,
        sbdf: PciSBDF,
        virtio_device: Arc<Mutex<VirtioPciDevice>>,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        let bar_address = {
            let mut device = virtio_device.lock().unwrap();

            device.register_notification_ioevents(vm)?;

            let sub_id = event_manager.add_subscriber(device.virtio_device());
            device.sub_id = Some(sub_id);

            device.bar_address()
        };

        self.virtio_devices
            .insert((device_type, id), virtio_device.clone());

        self.pci_segment
            .pci_bus
            .lock()
            .expect("Poisoned lock")
            .add_device(sbdf.device(), virtio_device.clone())?;

        debug!(
            "Inserting MMIO BAR region: {:#x}:{:#x}",
            bar_address, CAPABILITY_BAR_SIZE
        );
        vm.common
            .mmio_bus
            .insert(virtio_device.clone(), bar_address, CAPABILITY_BAR_SIZE)?;

        Ok(())
    }

    pub(crate) fn attach_pci_virtio_device(
        &mut self,
        vm: &Arc<KvmVm>,
        id: String,
        device: Arc<Mutex<dyn VirtioDevice>>,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        let sbdf = self.pci_segment.next_device_sbdf()?;
        debug!("Allocating SBDF: {sbdf:?} for device");

        let device_type = device.lock().expect("Poisoned lock").device_type();

        // Allocate one MSI vector per queue, plus one for configuration
        let msix_num =
            u16::try_from(device.lock().expect("Poisoned lock").queues().len() + 1).unwrap();

        let msix_vectors = KvmVm::create_msix_group(vm.clone(), msix_num)?;

        // Create the transport
        let mut virtio_device =
            VirtioPciDevice::new(id.clone(), vm, device, Arc::new(msix_vectors), sbdf);

        // Don't hold the resource allocator lock across attach_common()
        // below: a device access holds the bus lock and can take the allocator
        // lock, so the reverse order can deadlock.
        virtio_device.allocate_bars(&mut vm.resource_allocator().mmio32_memory)?;

        let virtio_device = Arc::new(Mutex::new(virtio_device));

        self.attach_common(vm, device_type, id, sbdf, virtio_device, event_manager)
    }

    pub(crate) fn pci_segment(&self) -> &PciSegment {
        &self.pci_segment
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn append_aml_bytes(
        &self,
        dsdt_data: &mut Vec<u8>,
    ) -> Result<(), acpi_tables::aml::AmlError> {
        use acpi_tables::Aml;

        self.pci_segment().append_aml_bytes(dsdt_data)
    }

    pub(crate) fn detach_pci_virtio_device(
        &mut self,
        vm: &KvmVm,
        device_id: VirtioDeviceId,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        let pci_device_arc = self
            .virtio_devices
            .remove(&device_id)
            .expect("device presence should be checked before detach");

        let sbdf_device = pci_device_arc.lock().expect("Poisoned lock").sbdf.device();

        // Remove the device from the PCI bus first. A config space access runs
        // with the PCI bus lock held and can relocate the BAR, so afterwards
        // the BAR address of the device can no longer change under us.
        self.pci_segment
            .pci_bus
            .lock()
            .expect("Poisoned lock")
            .remove_device(sbdf_device);

        // Next operations of removing device from mmio_bus and pci_bus need to wait for any other
        // user of the device to finish. This requires us to not hold the lock for the device in
        // case someone will try to access the device while we are in these several lines of code.
        let (bar_addr, sub_id) = {
            let pci_device = pci_device_arc.lock().expect("Poisoned lock");

            pci_device
                .unregister_notification_ioevents(vm)
                .map_err(PciManagerError::Kvm)?;
            (pci_device.bar_address(), pci_device.sub_id)
        };

        vm.common
            .mmio_bus
            .remove(bar_addr, CAPABILITY_BAR_SIZE)
            .map_err(PciManagerError::Bus)?;

        if let Some(sub_id) = sub_id
            && event_manager.remove_subscriber(sub_id).is_err()
        {
            warn!("Failed to remove event subscriber for device {device_id:?}");
        }

        pci_device_arc
            .lock()
            .expect("Poisoned lock")
            .free_bars(&mut vm.resource_allocator().mmio32_memory);

        // Ensure no other references to the device remain, so it is freed when
        // this function returns.
        assert_eq!(Arc::strong_count(&pci_device_arc), 1);

        Ok(())
    }

    /// Assign the host PCI functions described by `configs`, pairs of a Firecracker id and the
    /// host sysfs path of the function (e.g. `/sys/bus/pci/devices/0000:01:00.0`), to the guest.
    ///
    /// All functions are attached at once: they share one IOMMU context, and the BARs of all of
    /// them are placed together, largest first and from the top of each MMIO window, which packs
    /// naturally aligned power-of-two BARs without fragmentation and keeps them clear of the
    /// virtio-pci BARs allocated from the bottom of the window.
    pub(crate) fn attach_vfio_devices(
        &mut self,
        vm: &Arc<KvmVm>,
        configs: &[(String, &Path)],
    ) -> Result<(), PciManagerError> {
        if configs.is_empty() {
            return Ok(());
        }
        // Only one attach is supported: all the devices must share a single IOMMU context.
        assert!(self.vfio_context.is_none());

        let paths: Vec<&Path> = configs.iter().map(|&(_, path)| path).collect();
        let (context, opened) = VfioContext::new(vm, &paths)?;
        self.add_vfio_devices(
            vm,
            configs.iter().zip(opened).map(|((id, _), opened)| {
                move |sbdf: PciSBDF| VfioPciDevice::new(id.clone(), sbdf, opened, vm.clone())
            }),
        )?;
        self.vfio_context = Some(context);

        Ok(())
    }

    /// Add passthrough devices to the PCI bus, each built by its constructor at the SBDF it is
    /// given, then place and map the BARs of all of them.
    fn add_vfio_devices<F>(
        &mut self,
        vm: &Arc<KvmVm>,
        constructors: impl IntoIterator<Item = F>,
    ) -> Result<(), PciManagerError>
    where
        F: FnOnce(PciSBDF) -> Result<VfioPciDevice, VfioPciError>,
    {
        let mut devices = Vec::new();
        let mut intx_gsis = IntxGsis::default();
        for constructor in constructors {
            // The bus does not reserve the device ID it hands out: each device is added to the
            // bus before the next ID is taken.
            let sbdf = self.pci_segment.next_device_sbdf()?;
            let mut device = constructor(sbdf)?;
            debug!("Allocating SBDF: {sbdf:?} for VFIO device {}", device.id());
            if device.supports_intx() {
                let gsi = intx_gsis.next(&mut vm.resource_allocator())?;
                debug!("vfio: routing INTx of {} to GSI {gsi}", device.id());
                device.route_intx(gsi)?;
            }
            let device = Arc::new(Mutex::new(device));
            self.pci_segment
                .pci_bus
                .lock()
                .expect("Poisoned lock")
                .add_device(sbdf.device(), device.clone())?;
            devices.push(device);
        }

        let requirements: Vec<_> = devices
            .iter()
            .enumerate()
            .flat_map(|(device, vfio)| {
                vfio.lock()
                    .expect("Poisoned lock")
                    .bar_requirements()
                    .into_iter()
                    .map(move |requirement| (device, requirement))
            })
            .collect();
        let placements = place_vfio_bars(&mut vm.resource_allocator(), requirements)?;
        for (device, slot, guest_addr) in placements {
            devices[device]
                .lock()
                .expect("Poisoned lock")
                .place_bar(slot, guest_addr);
        }

        #[cfg(target_arch = "x86_64")]
        {
            // The ACPI PCI routing table of the segment maps INTA of each slot to its GSI.
            let pci_segment = &mut self.pci_segment;
            for device in &devices {
                let vfio = device.lock().expect("Poisoned lock");
                if let Some(gsi) = vfio.intx_gsi() {
                    pci_segment.pci_irq_slots[usize::from(vfio.sbdf().device())] =
                        u8::try_from(gsi).expect("x86 legacy GSIs fit in a byte");
                }
            }
        }

        for device in devices {
            let (id, ranges) = {
                let mut vfio = device.lock().expect("Poisoned lock");
                vfio.map_bars()?;
                (vfio.id().to_string(), vfio.mmio_ranges())
            };
            for (base, len) in ranges {
                debug!("vfio: trapping BAR range {base:#x}:{len:#x} on the MMIO bus");
                vm.common.mmio_bus.insert(device.clone(), base, len)?;
            }
            self.vfio_devices.insert(id, device);
        }

        Ok(())
    }

    /// Whether any VFIO passthrough device is currently attached.
    pub fn has_vfio_devices(&self) -> bool {
        !self.vfio_devices.is_empty()
    }

    /// The `(slot, GSI)` routes of the INTA pins of the devices on the PCI bus, by slot.
    pub fn intx_routes(&self) -> Vec<(u8, u32)> {
        let mut routes: Vec<(u8, u32)> = self
            .vfio_devices
            .values()
            .filter_map(|device| {
                let device = device.lock().expect("Poisoned lock");
                device.intx_gsi().map(|gsi| (device.sbdf().device(), gsi))
            })
            .collect();
        routes.sort_unstable();
        routes
    }

    fn restore_pci_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        vm: &Arc<KvmVm>,
        device: Arc<Mutex<T>>,
        device_id: &str,
        transport_state: &VirtioPciDeviceState,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        let device_type = device.lock().expect("Poisoned lock").device_type();

        let virtio_device = Arc::new(Mutex::new(VirtioPciDevice::new_from_state(
            device_id.to_string(),
            vm,
            device.clone(),
            transport_state.clone(),
        )?));

        self.attach_common(
            vm,
            device_type,
            device_id.to_string(),
            transport_state.sbdf,
            virtio_device,
            event_manager,
        )?;

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

    pub(crate) fn get_device(
        &self,
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        self.get_virtio_device(device_type, device_id)
            .map(|device| device.lock().expect("Poisoned lock").virtio_device())
    }

    pub(crate) fn contains_virtio_device(&self, device_id: &VirtioDeviceId) -> bool {
        self.virtio_devices.contains_key(device_id)
    }

    pub fn for_each_virtio_device(&self, mut f: impl FnMut(VirtioDeviceType, &dyn VirtioDevice)) {
        for ((device_type, _), pci_device) in &self.virtio_devices {
            let device_arc = pci_device.lock().expect("Poisoned lock").virtio_device();
            let device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &*device);
        }
    }

    pub(crate) fn for_each_virtio_device_mut(
        &self,
        mut f: impl FnMut(VirtioDeviceType, &mut dyn VirtioDevice),
    ) {
        for ((device_type, _), pci_device) in &self.virtio_devices {
            let device_arc = pci_device.lock().expect("Poisoned lock").virtio_device();
            let mut device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &mut *device);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioDeviceState<T> {
    /// Device identifier
    pub device_id: String,
    /// Device SBDF
    pub sbdf: PciSBDF,
    /// Device state
    pub device_state: T,
    /// Transport state
    pub transport_state: VirtioPciDeviceState,
}

/// First GSI INTx pins are routed to. On x86, the IOAPIC inputs from 16 up: KVM also wires GSIs 0
/// to 15 to the 8259 PIC, and PC chipsets route PCI interrupts to inputs 16 to 23 as well.
#[cfg(target_arch = "x86_64")]
const INTX_GSI_START: u32 = 16;
#[cfg(target_arch = "aarch64")]
const INTX_GSI_START: u32 = crate::arch::GSI_LEGACY_START;

/// The GSIs the INTx pins of passthrough devices are routed to: a GSI of its own for each device
/// while free ones are left, then the GSIs already used, in turn. INTx is level-triggered, so
/// devices can share a GSI, as they share interrupt lines on physical platforms.
#[derive(Debug, Default)]
struct IntxGsis {
    own: Vec<u32>,
    shared: usize,
}

impl IntxGsis {
    fn next(&mut self, allocator: &mut ResourceAllocator) -> Result<u32, vm_allocator::Error> {
        match allocator.allocate_gsi_legacy_from(INTX_GSI_START) {
            Ok(gsi) => {
                self.own.push(gsi);
                Ok(gsi)
            }
            Err(err) if self.own.is_empty() => Err(err),
            Err(_) => {
                let gsi = self.own[self.shared % self.own.len()];
                self.shared += 1;
                Ok(gsi)
            }
        }
    }
}

/// Choose the guest addresses of VFIO BARs, given as `(device, requirement)` pairs.
///
/// BARs are naturally aligned powers of two. Placing them largest first, each at the highest
/// suitable address of its window, packs them without fragmentation below the top of the window,
/// away from the virtio-pci BARs which are allocated from the bottom.
fn place_vfio_bars(
    allocator: &mut ResourceAllocator,
    mut requirements: Vec<(usize, BarRequirement)>,
) -> Result<Vec<(usize, BarSlot, u64)>, vm_allocator::Error> {
    // Stable sort: equally sized BARs keep the device and BAR order.
    requirements.sort_by_key(|(_, requirement)| std::cmp::Reverse(requirement.size));
    requirements
        .into_iter()
        .map(|(device, requirement)| {
            let window = match requirement.window {
                BarWindow::Mmio32 => &mut allocator.mmio32_memory,
                BarWindow::Mmio64 => &mut allocator.mmio64_memory,
            };
            let range = window.allocate(
                requirement.size,
                requirement.size,
                vm_allocator::AllocPolicy::LastMatch,
            )?;
            Ok((device, requirement.slot, range.start()))
        })
        .collect()
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PciDevicesState {
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
    pub vm: &'a Arc<KvmVm>,
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
    type Error = DevicePersistError;

    fn save(&self) -> Self::State {
        let mut state = PciDevicesState::default();

        for pci_dev in self.virtio_devices.values() {
            let locked_pci_dev = pci_dev.lock().expect("Poisoned lock");
            let virtio_dev = locked_pci_dev.virtio_device();
            // We need to call `prepare_save()` on the device before saving the transport
            // so that, if we modify the transport state while preparing the device, e.g. sending
            // an interrupt to the guest, this is correctly captured in the saved transport state.
            let mut locked_virtio_dev = virtio_dev.lock().expect("Poisoned lock");
            locked_virtio_dev.prepare_save();
            let transport_state = locked_pci_dev.state();

            let sbdf = transport_state.sbdf;

            match locked_virtio_dev.device_type() {
                VirtioDeviceType::Balloon => {
                    let balloon_device = locked_virtio_dev
                        .as_any()
                        .downcast_ref::<Balloon>()
                        .unwrap();

                    let device_state = balloon_device.save();

                    state.balloon_device = Some(VirtioDeviceState {
                        device_id: balloon_device.id().to_string(),
                        sbdf,
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
                            sbdf,
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
                        sbdf,
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

                    // Save state after potential notification to the guest. This
                    // way we save changes to the queue the notification can cause.
                    let vsock_state = VsockState {
                        backend: vsock_dev.backend().save(),
                        frontend: vsock_dev.save(),
                    };

                    state.vsock_device = Some(VirtioDeviceState {
                        device_id: vsock_dev.id().to_string(),
                        sbdf,
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
                        sbdf,
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
                        sbdf,
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
                        sbdf,
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
        let mut pci_devices = PciDevices::new(constructor_args.vm)?;

        if let Some(balloon_state) = &state.balloon_device {
            let device = Arc::new(Mutex::new(Balloon::restore(
                BalloonConstructorArgs { mem: mem.clone() },
                &balloon_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .balloon
                .set_device(device.clone());

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &balloon_state.device_id,
                &balloon_state.transport_state,
                constructor_args.event_manager,
            )?
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

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &block_state.device_id,
                &block_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        // Initialize MMDS if MMDS state is included.
        if let Some(mmds) = &state.mmds {
            constructor_args.vm_resources.set_mmds_basic_config(
                mmds.version,
                mmds.imds_compat,
                constructor_args.instance_id,
            )?;
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

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &net_state.device_id,
                &net_state.transport_state,
                constructor_args.event_manager,
            )?
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

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &vsock_state.device_id,
                &vsock_state.transport_state,
                constructor_args.event_manager,
            )?
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

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &entropy_state.device_id,
                &entropy_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        for pmem_state in &state.pmem_devices {
            let device = Arc::new(Mutex::new(Pmem::restore(
                PmemConstructorArgs {
                    mem,
                    vm: constructor_args.vm.clone(),
                },
                &pmem_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .pmem
                .configs
                .push(pmem_state.device_state.config.clone());

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &pmem_state.device_id,
                &pmem_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        if let Some(memory_device) = &state.memory_device {
            let ctor_args = VirtioMemConstructorArgs::new(Arc::clone(constructor_args.vm));
            let device = VirtioMem::restore(ctor_args, &memory_device.device_state)?;

            constructor_args.vm_resources.memory_hotplug = Some(MemoryHotplugConfig {
                total_size_mib: device.total_size_mib(),
                block_size_mib: device.block_size_mib(),
                slot_size_mib: device.slot_size_mib(),
            });

            let arcd_device = Arc::new(Mutex::new(device));
            pci_devices.restore_pci_device(
                constructor_args.vm,
                arcd_device,
                &memory_device.device_id,
                &memory_device.transport_state,
                constructor_args.event_manager,
            )?
        }

        // After PCI devices are restored, we must set up the GSI routes (one KVM_SET_GSI_ROUTING call for all vectors),
        // and enable all unmasked vectors (one kvm_irqfd call per vector).
        // Ordering: routing must be set before IRQFDs to avoid kernel panics on
        // older AMD/SVM hosts (see kernel commit a80ced6ea514).
        if !pci_devices.virtio_devices.is_empty() {
            constructor_args
                .vm
                .set_gsi_routes()
                .map_err(PciManagerError::from)?;

            for pci_device in pci_devices.virtio_devices.values() {
                let dev = pci_device.lock().expect("Poisoned lock");
                dev.enable_unmasked_vectors()
                    .map_err(PciManagerError::from)?;
            }
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
    use crate::vstate::resources::ResourceAllocator;

    #[test]
    fn test_device_manager_persistence() {
        // These need to survive so the restored blocks find them.
        let _block_files;
        let _pmem_files;
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();

        let serialized_data;
        let saved_allocator;
        // Set up a vmm with one of each device, and get the serialized DeviceStates.
        {
            let mut event_manager = EventManager::new().expect("Unable to create EventManager");
            let mut vmm = default_vmm_with_pci();
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
                mtu: None,
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
                ..Default::default()
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
            saved_allocator = vmm.vm.as_kvm().unwrap().resource_allocator().save()
        }

        tmp_sock_file.remove().unwrap();

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        // Keep in mind we are re-creating here an empty DeviceManager. Restoring later on
        // will create a new PciDevices manager different from vmm's virtio devices. We're
        // doing this to avoid restoring the whole Vmm, since what we really need from Vmm is the
        // KvmVm object and calling default_vmm() is the easiest way to create one.
        let vmm = default_vmm();
        // Restore the source allocator's state so the restored devices' GSIs match what their
        // `MsixVectorGroup::Drop` will try to free at end-of-test.
        *vmm.vm.as_kvm().unwrap().resource_allocator() =
            ResourceAllocator::restore((), &saved_allocator).unwrap();

        let device_manager_state: device_manager::DevicesState =
            bitcode::deserialize(&serialized_data).unwrap();
        let device_manager::VirtioDevicesState::Pci(pci_state) = &device_manager_state.virtio_state
        else {
            panic!("expected PCI virtio device state");
        };
        let vm_resources = &mut VmResources::default();
        let kvm_vm = vmm.vm.as_kvm().unwrap().clone();
        let restore_args = PciDevicesConstructorArgs {
            vm: &kvm_vm,
            mem: kvm_vm.guest_memory(),
            vm_resources,
            instance_id: "microvm-id",
            event_manager: &mut event_manager,
        };
        let _restored_dev_manager = PciDevices::restore(restore_args, pci_state).unwrap();

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
      "discard": false,
      "path_on_host": "{}",
      "rate_limiter": null,
      "io_engine": "Sync",
      "blk_size": 512,
      "topology": {{
        "physical_block_exp": 0,
        "alignment_offset": 0,
        "min_io_size": 0,
        "opt_io_size": 128
      }},
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
      "mtu": null,
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
      "read_only": true,
      "rate_limiter": null
    }}
  ],
  "vfio": [],
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
        assert_eq!(pci_state.mmds.as_ref().unwrap().version, MmdsVersion::V2);
        assert_eq!(
            expected_vm_resources,
            serde_json::to_string_pretty(&VmmConfig::from(&*vm_resources)).unwrap()
        );
    }

    #[test]
    fn test_place_vfio_bars() {
        use crate::arch::{
            MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START, MEM_64BIT_DEVICES_SIZE,
            MEM_64BIT_DEVICES_START,
        };
        use crate::devices::vfio::pci::{BarRequirement, BarSlot, BarWindow};

        let mut allocator = ResourceAllocator::new();
        // A virtio-pci BAR, allocated from the bottom of the 64-bit window.
        let virtio = allocator
            .mmio64_memory
            .allocate(
                CAPABILITY_BAR_SIZE,
                CAPABILITY_BAR_SIZE,
                vm_allocator::AllocPolicy::FirstMatch,
            )
            .unwrap()
            .start();
        let requirement = |slot, size, window| BarRequirement { slot, size, window };
        let half_window = MEM_64BIT_DEVICES_SIZE / 2;
        let requirements = vec![
            (0, requirement(BarSlot::Bar(0), 16 << 20, BarWindow::Mmio32)),
            (
                0,
                requirement(BarSlot::Bar(1), 256 << 20, BarWindow::Mmio64),
            ),
            (0, requirement(BarSlot::Bar(3), 32 << 20, BarWindow::Mmio64)),
            (0, requirement(BarSlot::Rom, 512 << 10, BarWindow::Mmio32)),
            (1, requirement(BarSlot::Bar(0), 16 << 20, BarWindow::Mmio32)),
            (
                1,
                requirement(BarSlot::Bar(1), half_window, BarWindow::Mmio64),
            ),
        ];
        let placements = place_vfio_bars(&mut allocator, requirements.clone()).unwrap();

        // Largest first; equal sizes keep their order.
        let order: Vec<(usize, BarSlot)> = placements
            .iter()
            .map(|&(device, slot, _)| (device, slot))
            .collect();
        assert_eq!(
            order,
            vec![
                (1, BarSlot::Bar(1)),
                (0, BarSlot::Bar(1)),
                (0, BarSlot::Bar(3)),
                (0, BarSlot::Bar(0)),
                (1, BarSlot::Bar(0)),
                (0, BarSlot::Rom),
            ]
        );
        // The largest BAR takes the top half of the 64-bit window, the next ones are packed right
        // below it, clear of the virtio-pci BAR.
        let top64 = MEM_64BIT_DEVICES_START + MEM_64BIT_DEVICES_SIZE;
        assert_eq!(placements[0].2, top64 - half_window);
        assert_eq!(placements[1].2, top64 - half_window - (256 << 20));
        assert_eq!(
            placements[2].2,
            top64 - half_window - (256 << 20) - (32 << 20)
        );
        assert!(placements[2].2 > virtio + CAPABILITY_BAR_SIZE);
        // Every BAR is naturally aligned and inside its window, and no two BARs overlap.
        for (&(device, slot, addr), i) in placements.iter().zip(0..) {
            let (_, requirement) = requirements
                .iter()
                .find(|(d, r)| *d == device && r.slot == slot)
                .unwrap();
            assert_eq!(addr % requirement.size, 0);
            let (start, size) = match requirement.window {
                BarWindow::Mmio32 => (MEM_32BIT_DEVICES_START, MEM_32BIT_DEVICES_SIZE),
                BarWindow::Mmio64 => (MEM_64BIT_DEVICES_START, MEM_64BIT_DEVICES_SIZE),
            };
            assert!(addr >= start && addr + requirement.size <= start + size);
            for &(other_device, other_slot, other_addr) in &placements[i + 1..] {
                let (_, other) = requirements
                    .iter()
                    .find(|(d, r)| *d == other_device && r.slot == other_slot)
                    .unwrap();
                assert!(addr + requirement.size <= other_addr || other_addr + other.size <= addr);
            }
        }

        // A BAR as large as the whole window no longer fits next to the virtio-pci BAR.
        let whole_window = vec![(
            0,
            requirement(BarSlot::Bar(0), MEM_64BIT_DEVICES_SIZE, BarWindow::Mmio64),
        )];
        place_vfio_bars(&mut ResourceAllocator::new(), whole_window.clone()).unwrap();
        place_vfio_bars(&mut allocator, whole_window).unwrap_err();
    }

    #[test]
    fn test_intx_gsis() {
        use crate::arch::GSI_LEGACY_END;

        let mut allocator = ResourceAllocator::new();
        let mut gsis = IntxGsis::default();
        // Each device gets a GSI of its own from INTX_GSI_START while some are free...
        let own: Vec<u32> = (INTX_GSI_START..=GSI_LEGACY_END)
            .map(|_| gsis.next(&mut allocator).unwrap())
            .collect();
        assert_eq!(own, (INTX_GSI_START..=GSI_LEGACY_END).collect::<Vec<_>>());
        // ...then they share the GSIs, in turn.
        let shared: Vec<u32> = (0..own.len() + 1)
            .map(|_| gsis.next(&mut allocator).unwrap())
            .collect();
        assert_eq!(shared[..own.len()], own);
        assert_eq!(shared[own.len()], own[0]);
        // With no GSI at all, routing fails.
        let mut allocator = ResourceAllocator::new();
        while allocator.allocate_gsi_legacy(1).is_ok() {}
        IntxGsis::default().next(&mut allocator).unwrap_err();
    }

    #[test]
    fn test_add_vfio_devices() {
        use crate::devices::vfio::pci::tests::{mock_vfio_device, setup_vm_with_irqchip};

        let vm = Arc::new(setup_vm_with_irqchip());
        let mut pci_devices = PciDevices::new(&vm).unwrap();
        let first = pci_devices.pci_segment.next_device_sbdf().unwrap().device();

        // The bus does not reserve the device IDs it hands out, yet every device gets a slot of
        // its own, as all the functions of an IOMMU group attached to one microVM need.
        let ids = ["gpu0", "audio0"];
        pci_devices
            .add_vfio_devices(
                &vm,
                ids.map(|id| {
                    let vm = vm.clone();
                    move |sbdf| Ok(mock_vfio_device(id, sbdf, vm))
                }),
            )
            .unwrap();
        let slot_of = |id: &str| pci_devices.vfio_devices[id].lock().unwrap().sbdf().device();
        assert_eq!(ids.map(&slot_of), [first, first + 1]);
        {
            let bus = pci_devices.pci_segment.pci_bus.lock().unwrap();
            for id in ids {
                assert!(bus.get_device(slot_of(id)).is_some());
            }
        }
        assert_eq!(
            pci_devices.pci_segment.next_device_sbdf().unwrap().device(),
            first + 2
        );

        // Each INTA pin is routed to a GSI of its own, for the slot of its device.
        let routes = pci_devices.intx_routes();
        let slots: Vec<u8> = routes.iter().map(|&(slot, _)| slot).collect();
        assert_eq!(slots, [first, first + 1]);
        assert_ne!(routes[0].1, routes[1].1);
        #[cfg(target_arch = "x86_64")]
        for (slot, gsi) in routes {
            let pci_irq_slot = pci_devices.pci_segment.pci_irq_slots[usize::from(slot)];
            assert_eq!(u32::from(pci_irq_slot), gsi);
        }

        // The BARs of the devices do not overlap.
        let mut ranges: Vec<(u64, u64)> = pci_devices
            .vfio_devices
            .values()
            .flat_map(|device| device.lock().unwrap().mmio_ranges())
            .collect();
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            assert!(pair[0].0 + pair[0].1 <= pair[1].0, "{pair:x?}");
        }
    }

    #[test]
    fn test_virtio_attach_without_mmio32_space() {
        use crate::devices::virtio::rng::Entropy;
        use crate::devices::virtio::transport::pci::device::CAPABILITY_BAR_SIZE;
        use crate::rate_limiter::RateLimiter;

        let mut vmm = default_vmm_with_pci();
        let vm = vmm.vm.as_kvm().unwrap().clone();
        // Passthrough BARs can take all the room left in the 32-bit MMIO window.
        {
            let mut allocator = vm.resource_allocator();
            while allocator
                .mmio32_memory
                .allocate(
                    CAPABILITY_BAR_SIZE,
                    CAPABILITY_BAR_SIZE,
                    vm_allocator::AllocPolicy::FirstMatch,
                )
                .is_ok()
            {}
        }

        // A virtio-pci device then fails to attach, without bringing the VMM down.
        let entropy = Arc::new(Mutex::new(Entropy::new(RateLimiter::default()).unwrap()));
        let mut event_manager = EventManager::new().unwrap();
        let err = device_manager::tests::pci_devices_mut(&mut vmm.device_manager)
            .attach_pci_virtio_device(&vm, "rng".to_string(), entropy, &mut event_manager)
            .unwrap_err();
        assert!(
            matches!(err, PciManagerError::ResourceAllocation(_)),
            "{err}"
        );
    }
}
